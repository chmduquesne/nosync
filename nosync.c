/*
 * Copyright 2012 Christophe-Marie Duquesne
 *
 * nosync, inspiration taken from
 * http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=310436
 *
 * This process is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This process is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this process.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <unistd.h>
#include <dlfcn.h>
#include <stdio.h>
#include <pwd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <syslog.h>

#define RUN_FILE "/var/run/nosync"
#define CONFIG_FILE "/etc/nosync.conf"
#define exists(file) (access(file, F_OK) != -1)

/* Rules in the config file */
typedef struct rule {
    char *user;
    char *process;
    bool *target;
    bool value;
} rule;

/* Pointers to the real sync, fsync, fdatasync. */
void (*__real_sync)(void) = NULL;
int (*__real_fsync)(int fd) = NULL;
int (*__real_fdatasync)(int fd) = NULL;

/* User, process running the library */
char user[32];
char process[256];

/*
 * Is the process using the lib authorized to use sync/fsync/fdatasync?
 * These values are statically determined from the user and process loadin
 * this library at config reading.
 */
bool sync_authorized = true;
bool fsync_authorized = true;
bool fdatasync_authorized = true;

/* Returns true if the calls should be redirected. */
bool enabled() {
    return exists(RUN_FILE);
}

/* user running the library */
int
inituser(){
    struct passwd *pw;
    uid_t uid;
    uid_t NO_UID = -1;
    uid = geteuid ();
    pw = (uid == NO_UID && errno ? NULL : getpwuid (uid));
    if (pw) {
        snprintf(user, 32, pw->pw_name);
        return 1;
    }
    return 0;
}

/* process running the library (taken from procfs) */
int
initprocess(){
    pid_t pid;
    char file[256];
    char buf[256];
    pid = getpid();
    snprintf(file, sizeof buf, "/proc/%i/cmdline", pid);
    FILE *f = fopen(file, "r");
    fgets(buf, sizeof buf, f);
    fclose(f);
    snprintf(process, sizeof process, buf);
    return 1;
}

/*
 * Parses a line of the config file. Returns true if the line is valid and
 * the rule should be applied
 */
bool
parseline(char *line, rule *r) {
    char *ptr, *rest, *token;
    if (!line || line[0] == '#')
        return false;
    r->user = NULL;
    r->target = NULL;
    r->process = NULL;
    r->value = true;
    ptr = line;
    token = strtok_r(ptr, " \n", &rest);
    ptr = rest;
    if (!token)
        return false;
    if (strncmp(token, "sync", sizeof "sync") == 0){
        r->target = &sync_authorized;
        r->value = true;
    }
    if (strncmp(token, "nosync", sizeof "nosync") == 0){
        r->target = &sync_authorized;
        r->value = false;
    }
    if (strncmp(token, "fsync", sizeof "fsync") == 0){
        r->target = &fsync_authorized;
        r->value = true;
    }
    if (strncmp(token, "nofsync", sizeof "nofsync") == 0){
        r->target = &fsync_authorized;
        r->value = false;
    }
    if (strncmp(token, "fdatasync", sizeof "fdatasync") == 0){
        r->target = &fdatasync_authorized;
        r->value = true;
    }
    if (strncmp(token, "nofdatasync", sizeof "nofdatasync") == 0){
        r->target = &fdatasync_authorized;
        r->value = false;
    }
    if (r->target == NULL){
        syslog(LOG_ERR, "unrecognized token: %s", token);
        return false;
    }

    while ((token = strtok_r(ptr, " \n", &rest)) != NULL){
        ptr = rest;
        if (strncmp(token, "user", sizeof "user") == 0) {
            token = strtok_r(ptr, " \n", &rest);
            ptr = rest;
            if (token == NULL) {
                syslog(LOG_ERR, "incomplete rule, missing user");
                return false;
            }
            r->user = token;
        }
        if (strncmp(token, "process", sizeof "process") == 0) {
            token = strtok_r(ptr, " \n", &rest);
            ptr = rest;
            if (token == NULL) {
                syslog(LOG_ERR, "incomplete rule, missing process");
                return false;
            }
            r->process = token;
        }
    }
    return true;
}

/* Read the rules line by line and apply them whenever they match */
void
readconfig(){
    char line[1024];
    rule r;
    if (!exists(CONFIG_FILE)){
        syslog(LOG_WARNING, "Config file %s not found", CONFIG_FILE);
        return;
    }
    FILE *f = fopen(CONFIG_FILE, "r");
    while (fgets(line, sizeof line, f) != NULL){
        if (parseline(line, &r)){
            /*
             * user/process matches when it was left unspecified by the
             * rule or if there is an actual match
             */
            if ((r.user == NULL || strcmp(r.user, user) == 0)
             && (r.process == NULL || strcmp(r.process, process) == 0)) {
                *(r.target) = r.value;
            }
        }
    }
}

/* Loads the sync symbols from libc */
void
initsymbols(void){
    void *handle;
    handle = dlopen("libc.so.6", RTLD_NOW|RTLD_LOCAL);
    if (!handle){
        syslog(LOG_CRIT, "error while loading library: %s", dlerror());
    }
    __real_sync = dlsym(handle, "sync");
    if (!__real_sync){
        syslog(LOG_CRIT, "error while fetching symbol sync: %s", dlerror());
    }
    __real_fsync = dlsym(handle, "fsync");
    if (!__real_fsync){
        syslog(LOG_CRIT, "error while fetching symbol fsync: %s", dlerror());
    }
    __real_fdatasync = dlsym(handle, "fdatasync");
    if (!__real_fdatasync){
        syslog(LOG_CRIT, "error while fetching symbol fdatasync: %s", dlerror());
    }
}

/* initialisation of the library */
void
init(){
    openlog ("libnosync", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
    inituser();
    initprocess();
    syslog (LOG_NOTICE, "loaded by program %s, user %s", process, user);
    initsymbols();
    readconfig();
}

/* Our sync replacement. Will actually sync only if authorized */
void
sync (void) {
    if (!__real_sync){
        init();
    }
    if (!enabled() || sync_authorized){
        return __real_sync();
    }
    syslog(LOG_INFO, "sync dismissed for process %s, user %s", process, user);
}

/* Our fsync replacement. Will actually fsync only if authorized */
int
fsync (int fd) {
    if (!__real_fsync){
        init();
    }
    if (!enabled() || fsync_authorized){
        return __real_fsync(fd);
    }
    syslog(LOG_INFO, "fsync dismissed for process %s, user %s\n", process, user);
    return 0;
}

/* Our fdatasync replacement. Will actually fdatasync only if authorized */
int
fdatasync (int fd) {
    if (!__real_fdatasync){
        init();
    }
    if (!enabled() || fdatasync_authorized){
        return __real_fdatasync(fd);
    }
    fprintf(stderr, "fdatasync dismissed for process %s, user %s\n", process, user);
    return 0;
}
