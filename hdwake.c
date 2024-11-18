#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>

#include <getopt.h>
#include <stdarg.h>
#include <libgen.h>

#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <linux/hdreg.h>
#include <linux/limits.h>

#include <asm/byteorder.h>

#include "sgio.h"

#define VER "0.0.3.6"
#define BUILDSTAMP ( __DATE__ " " __TIME__ )

#define DEF_CONF_PATH   "/etc/hdwake.conf"
#define DEF_DB_PATH     "/var/lib/hdwake/hdwake.db"
#define DEF_LOCK_PATH     "/var/lib/hdwake/hdwake.lock"


#define MAX_LINE_LENGTH 65536

#define START_MODEL             27  /* ASCII model number */
#define LENGTH_MODEL            20  /* 20 words (40 bytes or characters) */
#define START_SERIAL            10  /* ASCII serial number */
#define LENGTH_SERIAL           10  /* 10 words (20 bytes or characters) */




struct ActiveDevice {
    char * hdd_identity;
    uint32_t wakeup_timer;
    int apm;
    int standby;
    uint8_t disabled;
    uint8_t enable_protect_lcc;
    struct ActiveDevice * _next;

    uint64_t _actual_wakeup_count;
    uint64_t _last_lcc;
};

struct IdentityMap {
    char * dev_name;
    char * hdd_identity;
    struct IdentityMap * _next;
};

struct Cfg {
    char * config_path;
    char * db_path;
    char * lock_path;

    uint32_t identity_refresh_interval;

    uint32_t wakeup_timer_default;
    uint32_t wakeup_timer_min;
    uint32_t wakeup_count_protected_max;
    uint8_t apm_default;
    uint8_t standby_default;

    struct IdentityMap * _hdd_ids;
    struct ActiveDevice * _hdd_lists;

    uint64_t _t;
};

struct Cfg cfg;

void logger(const char * format, ...) {
    FILE * log_p = stdout;
    va_list args;
    va_start(args, format);
    vfprintf(log_p, format, args);
    va_end(args);
    fflush(log_p);
}

int mk_ensure_dir(const char * path) {
    int ret = 0;
    struct stat st;
    if (stat(path, &st) == -1) {
        if (mkdir(path, 0700) == 0) {
            ret = 1; // ok
        } else {
            ret = -1; // error when creating directory
        }
    } else if (S_ISDIR(st.st_mode)) {
        ret = 1; // already exists
    } else {
        ret = -1; // exists but is not a directory
    }
    return ret;
}

void prevent_dup_run(const char * lockfile) {
    int fd = open(lockfile, O_CREAT | O_RDWR, 0666);
    if (fd == -1) {
        fprintf(stdout, "error opening lock file: %s\n", lockfile);
        exit(1);
    }
    char pid_str[16];
    if (read(fd, pid_str, 16) < 0) {
        fprintf(stdout, "error reading lock file: %s\n", lockfile);
        exit(1);
    }
    if (flock(fd, LOCK_EX | LOCK_NB) == -1) { // exclusive lock (non-blocking)
        fprintf(stdout, "hdwake is already running: %s\n", pid_str);
        close(fd);
        exit(1);
    }
    if (ftruncate(fd, 0) == -1) {
        fprintf(stdout, "error truncating lock file: %s\n", lockfile);
        exit(1);
    }
    lseek(fd, 0, SEEK_SET);
    int n = snprintf(pid_str, 16, "%d", getpid());
    if (write(fd, pid_str, n) == -1) {
        fprintf(stdout, "error writing lock file: %s\n", lockfile);
        exit(1);
    }
}

int __pickup_ascii(__u16 *p, unsigned int length, char * out_buf, int out_bufsize) {
    int index = 0;

    __u8 ii;
    char cl;

    /* find first non-space & print it */
    for (ii = 0; ii< length; ii++) {
        if(((char) 0x00ff&((*p)>>8)) != ' ') break;
        if((cl = (char) 0x00ff&(*p)) != ' ') {
            if(cl != '\0') {
                if (index < out_bufsize) out_buf[index++] = (char) cl;
                // logger("%c",cl);
            }
            p++; ii++;
            break;
        }
        p++;
    }
    /* print the rest */
    for (; ii < length; ii++) {
        __u8 c;
        /* some older devices have NULLs */
        c = (*p) >> 8;
        if (c) {
            if (index < out_bufsize) out_buf[index++] = (char) c;
            // putchar(c);
        }
        c = (*p);
        if (c) {
            if (index < out_bufsize) out_buf[index++] = (char) c;
            // putchar(c);
        }
        p++;
    }
    
    // trim space from right side
    int j = 0;
    for (j = index - 1; j >= 0; j--) if (out_buf[j] != ' ') break;
    out_buf[j + 1] = 0;
    
    // replace space with _
    int sz = j + 1;
    for (j = 0; j < sz; j++) if (out_buf[j] == ' ') out_buf[j] = '_';

    return sz;
}


char * _get_hdd_identity(const char * dev_name) {
    __u16 *id = NULL;

    char device[PATH_MAX];
    snprintf(device, PATH_MAX, "/dev/%s", dev_name);

    int fd = open(device, O_RDONLY);  // Open the device as read-only
    if (fd < 0) {
        logger("failed to open (O_RDONLY) the device: %s\n", device);
        return NULL;
    }

    __u8 args[4+512];
    __u8 last_identify_op = 0;
    int prefer_ata12 = 0;
    int i;
    memset(args, 0, sizeof(args));
    last_identify_op = ATA_OP_IDENTIFY;
    args[0] = last_identify_op;
    args[3] = 1;    /* sector count */
    if (do_drive_cmd(fd, args, 0)) {
        // prefer_ata12 = 0;
        memset(args, 0, sizeof(args));
        last_identify_op = ATA_OP_PIDENTIFY;
        args[0] = last_identify_op;
        args[3] = 1;    /* sector count */
        if (do_drive_cmd(fd, args, 0)) {
            logger("HDIO_DRIVE_CMD (ATA_OP_IDENTIFY) failed\n");
            close(fd);
            return NULL;
        }
    }
    /* byte-swap the little-endian IDENTIFY data to match byte-order on host CPU */
    id = (void *)(args + 4);
    for (i = 0; i < 0x100; ++i)
        __le16_to_cpus(&id[i]);

    __u16 val[256];
    memcpy(val, id, sizeof(val));

    char model[64] = {0};
    char serial[64] = {0};
    if(val[START_MODEL]) {
        __pickup_ascii(&val[START_MODEL], LENGTH_MODEL, model, 64);
        // logger("Model Number:<%s>\n", model);
    }
    if(val[START_SERIAL]) {
        __pickup_ascii( &val[START_SERIAL], LENGTH_SERIAL, serial, 64);
        // logger("Serial Number:<%s>\n", serial);
    }

    char * hddid = (char *) malloc(4096 * sizeof(char));
    snprintf(hddid, 4096, "%s_%s", model, serial);

    close(fd);
    return hddid;
}

uint8_t * _get_hdd_smart(const char * dev_name) {
    char device[PATH_MAX];
    snprintf(device, PATH_MAX, "/dev/%s", dev_name);

    int fd = open(device, O_RDWR);
    if (fd < 0) {
        logger("failed to open (O_RDWR) the device: %s\n", device);
        return NULL;
    }

    __u8 args[4+512];
    memset(args, 0, sizeof(args));

    // when SMART
    // set in do_drive_cmd
    // cdb[6] = 0x4F;                // LBA Mid (7:0), SMART-specific value
    // cdb[7] = 0xC2;                // LBA High (7:0), SMART-specific value
    args[0] = ATA_OP_SMART;         // command, ATA SMART command (0xB0)
    args[1] = 0;                    // lbal, LBA Low (7:0), set to 0 for SMART
    args[2] = SMART_READ_VALUES;    // feature, SMART subcommand (e.g., SMART_READ_DATA = 0xD0)
    args[3] = 1;                    // nsect, Sector Count (7:0), set to 1 to read 512 bytes

    if (do_drive_cmd(fd, args, 0)) {
        logger("HDIO_DRIVE_CMD (ATA_OP_SMART_READ_DATA) failed\n");
        close(fd);
        return NULL;
    }
    close(fd);

    // Bytes 0-1: SMART Status Flag

    // Correct Structure of SMART Data Response (Modern Format)
    // SMART data for attributes is typically stored in a buffer of 512 bytes. Each attribute occupies 12 bytes, and the attributes begin at offset 2 in the buffer.

    // Offset   Length  Field           Description
    // 0        1       Attribute ID    Unique ID for the attribute (e.g., 0xC1 for Load_Cycle_Count).
    // 1-2      2       Attribute Flags Flags indicating status, criticality, etc. (little-endian).
    // 3        1       Current Value   Normalized value (e.g., percentage).
    // 4        1       Worst Value     Worst normalized value recorded.
    // 5-10     6       Raw Value       Actual data for the attribute (little-endian).
    // 11       1       Reserved        Reserved for future use.

    uint8_t * smart_data = malloc(512 * sizeof(uint8_t));
    memcpy(smart_data, args + 4, 512);
    return smart_data;
}

uint64_t __parse_smart_raw_value(uint8_t * raw_data) {
    uint64_t value_le = 0;
    memcpy(&value_le, raw_data, 6);
    return le64toh(value_le);
}

void hdd_get_ssc_lcc(const char * dev_name, uint64_t * out_ssc, uint64_t * out_lcc) {
    uint8_t * smart_data = _get_hdd_smart(dev_name);

    // ID#  ATTRIBUTE_NAME
    //   4  Start_Stop_Count
    // 193  Load_Cycle_Count

    int offset = 2; // skip the first 2 bytes (SMART Status Flag)

    uint64_t ssc = 0;
    uint64_t lcc = 0;
    while (offset + 12 <= 512) {
        uint8_t attr_id = smart_data[offset];        // Attribute ID
        if (attr_id == 4) { //   4  Start_Stop_Count
            ssc = __parse_smart_raw_value(smart_data + offset + 5);
        } else if (attr_id == 193) { // 193  Load_Cycle_Count
            lcc = __parse_smart_raw_value(smart_data + offset + 5);
        }
        offset += 12;
    }

    free(smart_data);

    if (out_ssc != NULL) *out_ssc = ssc;
    if (out_lcc != NULL) *out_lcc = lcc;
}

int hdd_set_standby(const char * dev_name, int standby) {
    int ret = 1;

    char device[PATH_MAX];
    snprintf(device, PATH_MAX, "/dev/%s", dev_name);

    int fd = open(device, O_RDWR);
    if (fd < 0) {
        logger("failed to open (O_RDWR) the device: %s\n", device);
        return -1;
    }

    __u8 args[4] = {ATA_OP_SETIDLE,standby,0,0};

    int get_standby = 1;
    if (get_standby) {
        logger(" Setting standby to %u\n", standby);
    }
    if (do_drive_cmd(fd, args, 0)) {
        // err = errno;
        logger("HDIO_DRIVE_CMD (ATA_OP_SETIDLE) failed\n");
        ret = -1;
    }

    close(fd);
    return ret;
}

int hdd_set_apmmode(const char * dev_name, int apmmode) {
    int ret = 1;

    char device[PATH_MAX];
    snprintf(device, PATH_MAX, "/dev/%s", dev_name);

    int fd = open(device, O_RDWR);
    if (fd < 0) {
        logger("failed to open (O_RDWR) the device: %s\n", device);
        return -1;
    }

    __u8 args[4] = {ATA_OP_SETFEATURES,0,0,0};

    int get_apmmode = 1;
    if (get_apmmode)
        logger(" Setting APM level to");
    if (apmmode==255) {
        /* disable Advanced Power Management */
        args[2] = 0x85; /* feature register */
        if (get_apmmode) logger(" disabled\n");
    } else {
        /* set Advanced Power Management mode */
        args[2] = 0x05; /* feature register */
        args[1] = apmmode; /* sector count register */
        if (get_apmmode)
            logger(" 0x%02x (%d)\n",apmmode,apmmode);
    }

    if (do_drive_cmd(fd, args, 0)) {
        // err = errno;
        logger("HDIO_DRIVE_CMD (ATA_OP_SETFEATURES) failed\n");
        ret = -1;
    }

    close(fd);
    return ret;
}

int hdd_powermode(const char * dev_name, char * state_desc, int state_desc_size) {
    // Reference:
    // hdparm -C /dev/sdc
    // smartctl -i -n standby /dev/sdc

    int ret = -1;

    char device[PATH_MAX];
    snprintf(device, PATH_MAX, "/dev/%s", dev_name);

    int fd = open(device, O_RDONLY);  // Open the device as read-only
    if (fd < 0) {
        logger("failed to open (O_RDONLY) the device: %s\n", device);
        return -1;
    }

    __u8 args[4] = {ATA_OP_CHECKPOWERMODE1,0,0,0};
    const char *state = "unknown";
    if (do_drive_cmd(fd, args, 0)
     && (args[0] = ATA_OP_CHECKPOWERMODE2) /* (single =) try again with 0x98 */
     && do_drive_cmd(fd, args, 0)) {
        int err = errno;
        logger("error, do_drive_cmd errno: %d\n", err);
    } else {
        switch (args[2]) {
            case 0x00: state = "standby"; ret = 0;      break;
            case 0x40: state = "NVcache_spindown"; ret = 3; break;
            case 0x41: state = "NVcache_spinup"; ret = 4;   break;
            case 0x80: state = "idle"; ret = 2;     break;
            case 0xff: state = "active/idle"; ret = 1;  break;
        }
    }

    // logger(" drive state is:  %s\n", state);
    if (state_desc != NULL) {
        snprintf(state_desc, state_desc_size, "%s", state);
    }

    close(fd);
    return ret;
}

void hdd_wake1(const char * dev_name) {
    char device[PATH_MAX];
    snprintf(device, PATH_MAX, "/dev/%s", dev_name);

    int fd = open(device, O_RDWR);  // Open the device as read-write to trigger wake up
    if (fd < 0) {
        logger("hdd_wake1 failed to open (O_RDONLY) the device: %s\n", device);
        return;
    }
    close(fd);
}

struct ActiveDevice * get_hdd_active_device(const char * hdd_identity) {
    struct ActiveDevice * ret = NULL;

    struct ActiveDevice * s = cfg._hdd_lists;
    while (s != NULL) {
        if (strcmp(s->hdd_identity, hdd_identity) == 0) {
            ret = s;
            break;
        }
        s = s->_next;
    }

    return ret;
}

void identity_clear() {
    // clear all the dict link
    struct IdentityMap * s = cfg._hdd_ids;
    while (s != NULL) {
        struct IdentityMap * curr = s;
        s = curr->_next;
        free(curr->dev_name);
        free(curr->hdd_identity);
        free(curr);
    }
    cfg._hdd_ids = NULL;
}

void identity_refresh() {
    identity_clear();

    // build a new dict
    const char * path = "/sys/block";
    struct stat info;
    DIR * dir = opendir(path);
    if (dir == NULL) {
        logger("error, failed to scan blocks sysfs\n");
        return;
    }
    struct dirent * entry;
    while ((entry = readdir(dir)) != NULL) {
        char full_path[PATH_MAX];
        snprintf(full_path, PATH_MAX, "%s/%s", path, entry->d_name);

        if (stat(full_path, &info) != 0) {
            logger("warning, failed to stat blocks path: %s, skip it\n", full_path);
            continue;
        }

        if (S_ISDIR(info.st_mode)) {
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) { // skip "." / ".."
                const char * dev_name = entry->d_name;
                if (strncmp(dev_name, "sd", 2) == 0) {
                    struct IdentityMap * new_id = (struct IdentityMap *) malloc(sizeof(struct IdentityMap));
                    memset(new_id, 0, sizeof(struct IdentityMap));
                    new_id->dev_name = strdup(dev_name); // copy it
                    new_id->hdd_identity = _get_hdd_identity(dev_name); // already copied it
                    new_id->_next = cfg._hdd_ids;
                    cfg._hdd_ids = new_id;
                }
            }
        }
    }
    closedir(dir);
}

void identity_print() {
    struct IdentityMap * s = cfg._hdd_ids;
    while (s != NULL) {
        char * dev_name = s->dev_name;

        char curr_powermode_str[16];
        int curr_powermode = hdd_powermode(dev_name, curr_powermode_str, 16);

        uint64_t ssc = 0;
        uint64_t lcc = 0;
        hdd_get_ssc_lcc(dev_name, &ssc, &lcc);

        fprintf(stdout, "%45s (/dev/%s): (%d) %s, Start_Stop_Count = %llu, Load_Cycle_Count = %llu\n", s->hdd_identity, dev_name, curr_powermode, curr_powermode_str, ssc, lcc);

        s = s->_next;
    }
}

char * identity_dev_name(const char * hdd_identity) {
    char * dev_name = NULL;
    struct IdentityMap * s = cfg._hdd_ids;
    while (s != NULL) {
        struct IdentityMap * curr = s;
        s = curr->_next;
        if (strcmp(hdd_identity, curr->hdd_identity) == 0) {
            dev_name = curr->dev_name;
            break;
        }
    }
    return dev_name;
}

void load_conf() {
    char line[MAX_LINE_LENGTH];

    logger("Loading config file: %s\n", cfg.config_path);
    FILE * f = fopen(cfg.config_path, "r");
    if (f == NULL) {
        logger("failed to open conf file: %s\n", cfg.config_path);
        exit(1);
    }

    // clear ActiveDevice _hdd_lists
    struct ActiveDevice * s = cfg._hdd_lists;
    while (s != NULL) {
        struct ActiveDevice * curr = s;
        s = curr->_next;
        free(curr->hdd_identity);
        free(curr);
    }
    cfg._hdd_lists = NULL;

    // read conf file
    while (fgets(line, MAX_LINE_LENGTH, f)) {
        struct ActiveDevice * curr = NULL;

        line[strcspn(line, "#\n")] = 0;
        char * token = strtok(line, " \t");
        uint32_t token_i = 0;
        while (token != NULL) {
            if (token_i == 0) {
                if (token != NULL && strlen(token) > 0) {
                    if (get_hdd_active_device(token) != NULL) {
                        logger("%s duplicated in conf file, skipped this one\n", token);
                        break;
                    }

                    curr = (struct ActiveDevice *) malloc(sizeof(struct ActiveDevice));
                    memset(curr, 0, sizeof(struct ActiveDevice));
                    curr->hdd_identity = strdup(token);
                    curr->wakeup_timer = cfg.wakeup_timer_default;
                    curr->apm = cfg.apm_default;
                    curr->standby = cfg.standby_default;
                }

            } else if (token_i == 1) {
                if (token[0] == '1') curr->disabled = 1;

            } else if (token_i == 2) {
                int _v = strtol(token, NULL, 0);
                if (_v > 255 || _v < 0) {
                    logger("Invalid APM value: %d, set to default: %d\n", _v, cfg.apm_default);
                    _v = cfg.apm_default;
                }
                curr->apm = _v;

            } else if (token_i == 3) {
                int _v = strtol(token, NULL, 0);
                if (_v > 255 || _v < 0) {
                    logger("Invalid Standby value: %d, set to default: %d\n", _v, cfg.standby_default);
                    _v = cfg.standby_default;
                }
                curr->standby = _v;

            } else if (token_i == 4) {
                if (token[0] == '1') curr->enable_protect_lcc = 1;

            }

            token = strtok(NULL, " \t");
            token_i++;
        }

        if (curr != NULL) {
            curr->_next = cfg._hdd_lists;
            cfg._hdd_lists = curr;
        }
    }

    fclose(f);

    logger("Loading DB file: %s\n", cfg.db_path);
    FILE * db_f = fopen(cfg.db_path, "r");
    if (db_f == NULL) {
        logger("DB unavailable, skipped. Check the directory...");

        char * _t = strdup(cfg.db_path);
        char * db_dir = dirname(_t);
        if (mk_ensure_dir(db_dir) == 1) {
            logger("ok\n");
        } else {
            logger("failed\n");
        }
        free(_t);
        return;
    }

    while (fgets(line, MAX_LINE_LENGTH, f)) {
        line[strcspn(line, "#\n")] = 0;
        char * item = strtok(line, " \t");
        uint32_t item_i = 0;
        struct ActiveDevice * active_hdd = NULL;
        while (item != NULL) {
            if (item_i == 0) {
                active_hdd = NULL;
                struct ActiveDevice * _a = get_hdd_active_device(item);
                if (_a != NULL) {
                    active_hdd = _a;
                    logger("%s loaded from DB\n", item);
                }

            } else if (item_i == 1) {
                if (active_hdd != NULL) {
                    uint32_t _v = strtoul(item, NULL, 0);
                    active_hdd->wakeup_timer = _v;
                    if (active_hdd->wakeup_timer < cfg.wakeup_timer_min) active_hdd->wakeup_timer = cfg.wakeup_timer_min;
                }

            } else if (item_i == 2) {
                if (active_hdd != NULL) {
                    uint32_t _v = strtoul(item, NULL, 0);
                    active_hdd->_actual_wakeup_count = _v;
                }

            }

            item = strtok(NULL, " \t");
            item_i++;
        }
    }

    fclose(db_f);
}

void hddlist_print() {
    struct ActiveDevice * s = cfg._hdd_lists;
    while (s != NULL) {
        logger("%s: %d\n", s->hdd_identity, s->disabled);
        s = s->_next;
    }
}

void update_db() {
    FILE * f = fopen(cfg.db_path, "w");
    if (f == NULL) {
        logger("Error opening db file: %s\n", cfg.db_path);
        return;
    }
    struct ActiveDevice * s = cfg._hdd_lists;
    while (s != NULL) {    
        fprintf(f, "%s\t%llu\t%llu\n", s->hdd_identity, s->wakeup_timer, s->_actual_wakeup_count);
        s = s->_next;
    }
    fclose(f);
}

void wakeup_loop() {
    logger("Entering wakeup loop\n");
    while(1) {
        if (cfg._t % cfg.identity_refresh_interval == 0) {
            identity_refresh();
            logger("Identity map refreshed\n");
        }

        struct ActiveDevice * s = cfg._hdd_lists;
        while (s != NULL) {
            if (s->disabled != 1 && cfg._t % s->wakeup_timer == 0) {
                if (s->_actual_wakeup_count < cfg.wakeup_count_protected_max) {
                    char * curr_identity = s->hdd_identity;
                    char * curr_devname = identity_dev_name(curr_identity);

                    uint64_t lcc = 0;
                    hdd_get_ssc_lcc(curr_devname, NULL, &lcc);

                    char curr_powermode_str[16];
                    int curr_powermode = hdd_powermode(curr_devname, curr_powermode_str, 16);
                    logger("Checking %s (/dev/%s), current powermode: (%d) %s, Load_Cycle_Count: %llu\n", curr_identity, curr_devname, curr_powermode, curr_powermode_str, lcc);

                    if (cfg._t > 0) {
                        if ((curr_powermode != 1) || (s->_last_lcc < lcc)) {
                            s->_actual_wakeup_count++;
                            uint32_t __wakeup_timer_orin = s->wakeup_timer;
                            s->wakeup_timer *= 0.75;
                            if (s->wakeup_timer < cfg.wakeup_timer_min) s->wakeup_timer = cfg.wakeup_timer_min;
                            logger("Punish %s (/dev/%s), wakeup_timer: %u -> %u, actual_wakeup_count: %u\n", curr_identity, curr_devname, __wakeup_timer_orin, s->wakeup_timer, s->_actual_wakeup_count);
                            update_db();
                        }
                    }
                    s->_last_lcc = lcc;

                    hdd_wake1(curr_devname);

                } else {
                    logger("actual_wakeup_count on %s (/dev/%s) reached max protected limit: %u\n, for your HDD safety, nothing will be done then. It seems that your device is not suitable to use hdwake. Or you may want to delete the line on DB file to retry\n");
                }
            }

            s = s->_next;
        }

        cfg._t++;
        sleep(1);
    }
}

void init_apm_standby() {
    struct ActiveDevice * s = cfg._hdd_lists;
    while (s != NULL) {
        char * curr_identity = s->hdd_identity;
        char * curr_devname = identity_dev_name(curr_identity);
        logger("%s (/dev/%s):\n", curr_identity, curr_devname);
        hdd_set_apmmode(curr_devname, s->apm);
        hdd_set_standby(curr_devname, s->standby);
        if (s->enable_protect_lcc) {
            logger(" Protect LCC enabled\n");
        } else {
            logger(" Protect LCC disabled\n");
        }
        s = s->_next;
    }
}

int action_list(int argc, char ** argv, int _argc, char ** _argv) {
    identity_refresh();
    identity_print();

    exit(0);
    return 0;
}

static void usage_run() {
    fprintf(stdout,
        "Usage: hdwake run [...]\n\n"
        "Options:\n"
        "  -c <path>    Specify hdwake config file path, default: %s\n"
        "  -j <path>    Specify hdwake DB file path, default: %s\n"
        "  -h           Show this help message\n"
        "\n",
        DEF_CONF_PATH, DEF_DB_PATH
    );
}

int action_run(int argc, char ** argv, int _argc, char ** _argv) {
    char * param_config_file = NULL;
    char * param_db_file = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "c:j:h")) != -1) {
        switch (opt) {
            case 'c':
                param_config_file = strdup(optarg);
            break;

            case 'j':
                param_db_file = strdup(optarg);
            break;

            case 'h':
            default:
                usage_run();
                exit(0);
            break;
        }

    }

    memset(&cfg, 0, sizeof(struct Cfg));
    cfg.wakeup_timer_min = 10;
    cfg.wakeup_timer_default = 10 * 60;
    cfg.wakeup_count_protected_max = 128;
    cfg.identity_refresh_interval = 5 * 60;
    cfg.apm_default = 254;
    cfg.standby_default = 0;
    cfg.lock_path = DEF_LOCK_PATH;

    cfg.config_path = DEF_CONF_PATH;
    if (param_config_file != NULL) {
        cfg.config_path = param_config_file;
    }

    cfg.db_path = DEF_DB_PATH;
    if (param_db_file != NULL) {
        cfg.db_path = param_db_file;
    }

    char * _t = strdup(cfg.lock_path);
    char * lock_dir = dirname(_t);
    if (mk_ensure_dir(lock_dir) != 1) {
        logger("Checking lock directory failed\n");
        exit(1);
    }
    free(_t);
    prevent_dup_run(cfg.lock_path);

    nice(19);

    logger("Starting hdwake [ver %s, by XXSL, build on %s]\n", VER, BUILDSTAMP);

    load_conf();
    identity_refresh();
    init_apm_standby();

    wakeup_loop();

    return 0;
}

static void usage() {
    fprintf(stdout,
        "hdwake [ver %s, by XXSL, build on %s]\n\n"
        "Usage: \n"
        "    hdwake list | run\n\n"
        "    Use --help or -H to see more details\n\n", VER, BUILDSTAMP
    );
}

int main(int argc, char ** argv, char ** env) {
    if (argc <= 1) {
        usage();
        return 0;
    }

    int action = 0;
    if ((!strcmp(argv[1], "list")) || (!strcmp(argv[1], "ls"))) {
        action = 1;

    } else if (!strcmp(argv[1], "run")) {
        action = 2;

    } else if (!strcmp(argv[1], "debug")) {
        _get_hdd_smart("sdc");

    } else {
        usage();
        return 0;
    }

    int action_argc = argc - 1;
    char ** action_argv = argv + 1;
    switch (action) {
        case 1:
            action_list(action_argc, action_argv, argc, argv);
        break;
        case 2:
            action_run(action_argc, action_argv, argc, argv);
        break;
    }
    return 0;
}
