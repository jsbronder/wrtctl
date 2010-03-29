/*
 * Copyright (c) 2009, 3M
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the 3M nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Justin Bronder <jsbronder@brontes3d.com>
 */

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <alloca.h>

#include "wrtctl-net.h"

#define SYS_CMDS_MODVER 1
#define SYS_CMDS_NAME "sys-cmds"
#define CTX_CAST(x,y) sysh_ctx_t x = (sysh_ctx_t)y

#define ROUTE_PATH "/proc/net/route"

char mod_name[] = SYS_CMDS_NAME;
char mod_magic_str[MOD_MAGIC_LEN] = "SYS";
int  mod_version = SYS_CMDS_MODVER;
char mod_errstr[MOD_ERRSTR_LEN];

int     mod_init        (void **ctx);
void    mod_destroy     (void *ctx);
int     mod_handler     (void *ctx, net_cmd_t cmd, packet_t *outp);


typedef struct sysh_ctx {
    char    *initd_dir;
} *sysh_ctx_t;

int     sys_cmd_initd       (sysh_ctx_t syshc, char *value, uint16_t *out_rc, char **out_str);
int     sys_cmd_route_info  (sysh_ctx_t syshc, char *value, uint16_t *out_rc, char **out_str);
int     sys_cmd_ip_info     (sysh_ctx_t syshc, char *value, uint16_t *out_rc, char **out_str);
int     sys_cmd_dns_info    (sysh_ctx_t syshc, char *value, uint16_t *out_rc, char **out_str);

int mod_init(void **mod_ctx){
    int rc = MOD_OK;
    sysh_ctx_t ctx = NULL;
    char *initd_dir = NULL;

    *mod_ctx = NULL;
    
    if ( !(ctx = (sysh_ctx_t)malloc(sizeof(struct sysh_ctx))) ){
        rc = MOD_ERR_MEM;
        goto err;
    }
    ctx->initd_dir = NULL;

    initd_dir = getenv("WRTCTL_SYS_INITD_DIR");
    if ( !initd_dir )
        initd_dir = "/etc/init.d/";
    if ( !(ctx->initd_dir = strdup(initd_dir)) ){
        rc = MOD_ERR_MEM;
        goto err;
    }

    (*mod_ctx) = ctx;
    return rc;

err:
    if( ctx ) mod_destroy((void*)ctx);
    return rc;
}

void mod_destroy(void *ctx){
    CTX_CAST(syshc, ctx);
    if ( ctx ){
        if ( syshc->initd_dir ) 
            free(syshc->initd_dir);
        free(syshc);
    }
    return;
}

int mod_handler(void *ctx, net_cmd_t cmd, packet_t *outp){
    int rc = MOD_OK;
    CTX_CAST(syshc, ctx);
    uint16_t out_rc;
    char *out_str = NULL;

    info("sys-cmds_handler in: cmd=%u, args='%s'\n",
        cmd->id, cmd->value ? cmd->value : "(null)");

    switch ( cmd->id ){
        case SYS_CMD_INITD:
            rc = sys_cmd_initd(syshc, cmd->value, &out_rc, &out_str);
            break;
        case SYS_CMD_ROUTE_INFO:
            rc = sys_cmd_route_info(syshc, cmd->value, &out_rc, &out_str);
            break;
        case SYS_CMD_IP_INFO:
            rc = sys_cmd_ip_info(syshc, cmd->value, &out_rc, &out_str);
            break;
        case SYS_CMD_DNS_INFO:
            rc = sys_cmd_dns_info(syshc, cmd->value, &out_rc, &out_str);
            break;
        default:
            err("sys-cmds_handler:  Unknown command '%u'\n", cmd->id);
            out_rc = NET_ERR_INVAL;
            if ( asprintf(&out_str, "Unknown command") == -1 ){
                err("asprintf: %s\n", strerror(errno));
                out_str = NULL;
            }
            break;
    }
    rc = create_net_cmd_packet(outp, out_rc, SYS_CMDS_MAGIC, out_str);
    if ( out_rc != NET_OK )
        err("sys-cmds_handler returned %u, %s\n",
            out_rc, out_str ? out_str : "-" );
    if ( out_str )
        free(out_str);
    return rc;
}

int sys_cmd_initd(sysh_ctx_t syshc, char *value, uint16_t *out_rc, char **out_str){
    int sys_rc = MOD_OK;
    int rc = 0;
    pid_t pid;
    char *dpath, *daemon, *command, *p;
    static char *valid_commands[] = {"restart", "stop", "start", "reload", "enable", "disable", NULL};
    size_t len;
    bool valid = false;
    int i;
    
    dpath = daemon = command = p = NULL;

    if ( !value || !(p = strchr(value, ' '))  ){
        sys_rc = EINVAL;
        if ( asprintf(out_str, "Invalid argument list.") == -1 ){
            err("asprintf: %s\n", strerror(errno));
            *out_str = NULL;
        }
        goto done;
    }

    *p = '\0';
    daemon = strdup(value);
    *p = ' ';
    if ( asprintf(&dpath, "%s/%s", syshc->initd_dir, basename(daemon)) < 0 ){
        sys_rc = ENOMEM;
        goto done;
    }
    if ( access(dpath, X_OK) != 0 ){
        sys_rc = EPERM;
        if ( asprintf(out_str, "access:  %s", strerror(errno)) == -1 ){
            err("asprintf: %s\n", strerror(errno));
            *out_str = NULL;
        }
        goto done;
    }


    command = strdup(p+1);
    for (i=0; valid_commands[i]; i++){
        len = strlen(valid_commands[i]);
        if ( strnlen(command, len+1) != len )
            continue;
        if ( !strncmp(command, valid_commands[i], len) ){
            valid = true;
            break;
        }
    }

    if ( !valid ){
        sys_rc = EINVAL;
        if ( asprintf(out_str, "Invalid init command.") == -1 ){
            err("asprintf: %s\n", strerror(errno));
            *out_str = NULL;
        }
        goto done;
    }

    pid = fork();
    if ( pid == -1 ){
        sys_rc = errno;
        if ( asprintf(out_str, "fork:  %s", strerror(errno)) == -1 ){
            err("asprintf: %s\n", strerror(errno));
            *out_str = NULL;
        }
        goto done;
    }

    
    if ( pid == 0 ){
        char *argv[] = { dpath, command, NULL };
        char *envir[] = { NULL };
        rc = execve(dpath, argv, envir);
        exit(EXIT_FAILURE);
    } else {
        int status;
        /* Wait for the child to exit and grab the rc. */
        if ( waitpid( pid, &status, 0) != pid ){
            sys_rc = errno;
            if ( asprintf(out_str, "waitpid:  %s", strerror(errno)) ){
                err("asprintf: %s\n", strerror(errno));
                *out_str = NULL;
            }
            goto done;
        }
        if ( !(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS) ){
            sys_rc = ECANCELED;
            if ( asprintf(out_str, "%s exited with failure.\n", daemon) == -1 ){
                err("asprintf: %s\n", strerror(errno));
                *out_str = NULL;
            }
        }
    }

    if ( asprintf(out_str, "%s %s success.\n", daemon, command) == -1 ){
        err("asprintf: %s\n", strerror(errno));
        *out_str = NULL;
    }

done:
    if (daemon) free(daemon);
    if (dpath) free(dpath);
    if (command) free(command);
    (*out_rc) = (uint16_t)sys_rc;
    return rc;
}

/* Network to IP address string */
int ntoip_str(char *str){
    int i;
    char t;
    char *s = NULL;
    struct in_addr addr = {(in_addr_t)0};
    static char buf[32];

    if ( !str || strlen(str) < 8 || strlen(str) > 30 ){
        return EINVAL;
    }

    for ( i = 0; i < 2; i++ ){
        t = str[6+i];
        str[6+i] = str[i];
        str[i] = t;

        t = str[4+i];
        str[4+i] = str[2+i];
        str[2+i] = t;
    }
    
    sprintf(buf, "0x%s", str);
    if ( inet_aton(buf, &addr) == 0 ){
        *str = '\0';
        return errno;
    }
       
    s = inet_ntoa(addr);
    memcpy(str, s, strlen(s)+1);
    return 0;
}
        

/*
 * Parses /proc/net/route to grab every triplet of
 * destination, gateway, interface.  Return is a
 * big string with each triplet on a seperate line
 * and ip addresses seperated by colons.
 */
int sys_cmd_route_info(sysh_ctx_t syshc, char *value, uint16_t *out_rc, char **out_str){
    int sys_rc = MOD_OK;
    int rc = 0;
    FILE *fd = NULL;
    char *p;
    char *err = NULL;
    char *realloc_save;
    char *buf = NULL;
    size_t buf_len, buf_used, def_len;
    char line[1024];
    char iface[32];
    char gateway[32];
    char dest[32];

    if ( access(ROUTE_PATH, R_OK) != 0 ){
        sys_rc = EPERM;
        if ( asprintf(out_str, "access:  %s", strerror(errno)) == -1 ){
            err("asprintf: %s\n", strerror(errno));
            *out_str = NULL;
        }
        goto done;
    }

    if ( !(fd = fopen(ROUTE_PATH, "r")) ){
        sys_rc = errno;
        if ( asprintf(out_str, "access: %s", strerror(errno)) == -1 ){
            err("asprintf: %s\n", strerror(errno));
            *out_str = NULL;
        }
        goto done;
    }

    if ( !(buf = malloc(128)) ){
        sys_rc = errno;
        if ( asprintf(out_str, "malloc: %s", strerror(errno)) == -1 ){
            err("asprintf: %s\n", strerror(errno));
            *out_str = NULL;
        }
        goto done;
    }
    buf_len = 128;
    buf_used = 1;
    buf[0] = '\0';

    /*
     * Ignore the first line which is just table names.
     */
    while ( fgetc(fd) != '\n' && feof(fd) == 0 ) {;}

    while ( fgets(line, 1024, fd) ){
        if ( strnlen(line, 1023) >= 1023 ) {
            sys_rc = EINVAL;
            err = "Parse error, line too long";
            break;
        }

        if ( !( p = strtok(line, "\t")) || strnlen(p, 31) >= 31 ){
            sys_rc = EINVAL;
            err = "Parse error, no iface";
            break;
        }
        sprintf(iface, "%s", p);
        
        if ( !( p = strtok(NULL, "\t")) || strnlen(p, 31) >= 31 ){
            sys_rc = EINVAL;
            err = "Parse error, no destination";
            break;
        }
        sprintf(dest, "%s", p);
         
        if ( !( p = strtok(NULL, "\t")) || strnlen(p, 31) >= 31 ){
            sys_rc = EINVAL;
            err = "Parse error, no gateway";
            break;
        }
        sprintf(gateway, "%s", p);

        ntoip_str(dest);
        ntoip_str(gateway);

        /* 'dest:gateway:iface\n' */
        def_len = strlen(dest) + strlen(gateway) + strlen(iface) + 3;
        if ( buf_len <  buf_used + def_len ) {
            realloc_save = realloc(buf, buf_len+128+def_len);
            if ( !realloc_save ){
                sys_rc = errno;
                free(buf);
                if ( asprintf(out_str, "realloc: %s", strerror(errno)) == -1 ){
                    err("asprintf: %s\n", strerror(errno));
                }
                goto done;
            }
            buf = realloc_save;
            buf_len += 128 + def_len;
        }
        
        sprintf( buf+buf_used-1, "%s:%s:%s\n", dest, gateway, iface);
        buf_used += def_len;
    }
   
    if ( err != NULL ){
        if ( asprintf(out_str, "%s", err) == -1 ){
            err("asprintf: %s\n", strerror(errno));
            *out_str = NULL;
        }
        goto done;
    } 

    if ( !(*out_str = strdup(buf)) ){
        if ( asprintf(out_str, "strdup: %s", strerror(errno)) == -1 ){
            err("asprintf: %s\n", strerror(errno));
            *out_str = NULL;
        }
        goto done;
    }
    free(buf);
    buf = NULL;
    fclose(fd);
    fd = NULL;

done: 
    if ( fd )
        fclose(fd);
    if ( buf )
        free(buf);
    (*out_rc) = (uint16_t)sys_rc;
    return rc;
}

/*
 * Returns a list of network interfaces and their ipv4 address.
 * <interface>:<address>\n
 */
int sys_cmd_ip_info(sysh_ctx_t syshc, char *value, uint16_t *out_rc, char **out_str){
    int sys_rc = MOD_OK;
    int rc = 0;
    int sock = -1;
    struct ifreq *ifreqs = NULL;
    size_t ifreqs_len = 4 * sizeof(struct ifreq);
    struct ifconf ic;
    int i;
    size_t buf_len = 1024;
    size_t buf_used = 0;

    if ( !( (*out_str) = (char*)malloc(buf_len)) ){
        if ( asprintf(out_str, "malloc: %s", strerror(errno)) == -1 ){
            err("asprintf: %s\n", strerror(errno));
            *out_str = NULL;
        }
        goto done;
    }

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    while ( true ){
        if ( !(ifreqs = (struct ifreq *)malloc(ifreqs_len)) ){
            sys_rc = errno;
            if ( asprintf(out_str, "malloc: %s", strerror(errno)) == -1 ){
                err("asprintf: %s\n", strerror(errno));
                *out_str = NULL;
            }
            goto done;
        }
        ic.ifc_len = ifreqs_len;
        ic.ifc_req = ifreqs;
        ioctl(sock, SIOCGIFCONF, &ic);
        if ( ic.ifc_len == ifreqs_len ) {
            free(ifreqs);
            ifreqs_len += 4 * sizeof(struct ifreq);
            continue;
        }
        break;
    }
    close(sock);
    sock = -1;

    **out_str = '\0';
    for ( i = 0; i < ic.ifc_len/sizeof(struct ifreq); i++ ) {
        if ( buf_len - buf_used - strlen(ifreqs[i].ifr_name) - 16 ) {
            if ( !((*out_str) = realloc((*out_str), buf_len + 1024)) ){
                sys_rc = errno;
                free((*out_str));
                if ( asprintf(out_str, "realloc: %s", strerror(errno)) == -1 ){
                    err("asprintf: %s\n", strerror(errno));
                    *out_str = NULL;
                }
                goto done;
            }
        }
        sprintf( (*out_str) + strlen((*out_str)), "%s:%s\n",
            ifreqs[i].ifr_name,
            inet_ntoa( ((struct sockaddr_in*)&ifreqs[i].ifr_addr)->sin_addr ) );
        buf_used = strlen((*out_str)) + 1;
    }

done:
    if ( sock > 0 )
        close(sock);
    (*out_rc) = (uint16_t)sys_rc;
    return rc;
}


int parse_nameservers(char *path, char **out_str, bool *has_localhost) {
    FILE *fd = NULL;
    char *buf = NULL;
    char *err = NULL;
    size_t buf_len, buf_used, nsl;
    char *p, *realloc_save;
    char line[1024];
    int rc = 0;

    *has_localhost = false;

    if ( !(buf = (char*)malloc(128)) ){
        rc = errno;
        if ( asprintf(out_str, "malloc: %s", strerror(errno)) == -1 ){
            err("asprintf: %s\n", strerror(errno));
            *out_str = NULL;
        }
        goto done;
    }
    buf[0] = '\0';
    buf_used = 1;
    buf_len = 128;

    if ( !(fd = fopen(path, "r")) ){
        rc = errno;
        if ( asprintf(out_str, "fopen(%s): %s", path, strerror(errno)) == -1 ){
            err("asprintf: %s\n", strerror(errno));
            *out_str = NULL;
        }
        goto done;
    }

    while ( fgets(line, 1024, fd) ){
        if ( strnlen(line, 1023) >= 1023 ) {
            rc = EINVAL;
            err = "Parse error, line too long";
            break;
        }
       
        if ( strncmp(line, "nameserver", strlen("nameserver")) )
            continue;

        if ( !( p = strtok(line, "\t ")) 
                || !(p = strtok(NULL, "\t \n"))
                || (nsl = strnlen(p, 31)) >= 31 ) {
            rc = EINVAL;
            err = "Parse error, invalid nameserver";
            break;
        }
       
        if ( buf_len < buf_used + nsl + 1 ){
            realloc_save = realloc(buf, buf_len + 128);
            if ( !realloc_save ){
                rc = errno;
                free(buf);
                if ( asprintf(out_str, "realloc: %s", strerror(errno)) == -1 ){
                    err("asprintf: %s\n", strerror(errno));
                }
                goto done;
            }
            buf = realloc_save;
            buf_len += 128;
        }
        sprintf(buf+buf_used-1, "%s\n", p);
        buf_used += nsl+1;
 
        if ( !strncmp(p, "127.0.0.1", 10) )
            *has_localhost = true;
    }

    if ( err != NULL ){
        if ( asprintf(out_str, "%s", err) == -1 ){
            err("asprintf: %s\n", strerror(errno));
            *out_str = NULL;
        }
        goto done;
    } 

    if ( !(*out_str = strdup(buf)) ){
        if ( asprintf(out_str, "strdup: %s", strerror(errno)) == -1 ){
            err("asprintf: %s\n", strerror(errno));
            *out_str = NULL;
        }
        goto done;
    }
    free(buf);
    buf = NULL;
    fclose(fd);
    fd = NULL;

done:
    if ( buf )
        free(buf);
    if ( fd )
        fclose(fd);
    return rc;
} 
    

/*
 * Returns a list of nameservers.  Checks for /tmp/resolv.conf.auto which is
 * used by dnsmasq on OpenWRT if 127.0.0.1 is set in /etc/resolv.conf.
 */
int sys_cmd_dns_info(sysh_ctx_t syshc, char *value, uint16_t *out_rc, char **out_str){
    int sys_rc = MOD_OK;
    bool check_tmp = false;

    *out_str = NULL;
    sys_rc = parse_nameservers("/etc/resolv.conf", out_str, &check_tmp);
    
    if ( sys_rc == 0 
            && check_tmp
            && !access("/tmp/resolv.conf.auto", R_OK) ){
        if ( *out_str )
            free(*out_str);
        sys_rc = parse_nameservers("/tmp/resolv.conf.auto", out_str, &check_tmp);
    }
    
    *out_rc = sys_rc;
    return 0;
}

