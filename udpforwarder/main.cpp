//
//  main.cpp
//  udpforwarder
//
//  Created by Shakthi Prasad G S on 23/10/16.
//  Copyright © 2016 self. All rights reserved.
//

#include <iostream>

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

/* udp-repeater
 *
 * example of use
 *
 *   udp-repeater -p 6180 -s destination1.net -s destination2.net:9199
 *
 * This causes udp-repeater to listen on the local matchine (port 6180;
 * you can also bind a particular local IP address with the -l flag).
 * Whenever a UDP datagram is received, it is re-sent to each destination
 * (specified with the -s flag) on the same port as we received it on,
 * or to the specified port (:9199) for a particular destination.
 *
 * To test it, run udp-repeater with appropriate arguments, set up a sink
 * to receive the datagrams somewhere, like:
 *
 *   destination1% nc -l -u 6180
 *
 * then generate some UDP datagrams to the repeater, e.g.,
 *
 *   somewhere% echo hi | nc -4 -u repeater-host 6180
 *
 * you sould see the udp datagram repeated on destination1.
 *
 * NOTE: when using nc to generate traffic, if you omit the -4 flag
 *       and use a name (such as localhost) instead of an IPv4 address
 *       nc will use an IPv6 UDP datagram, which udp-repeater does not
 *       currently accept.
 *
 */

#define BUFSZ 2000
char buf[BUFSZ];
char *ip;
int port;
int sourceport = -1;
int verbose;
char *prog;


struct sockaddr_in dest;

void usage() {
    fprintf(stderr, "usage: %s [-v] [-l <bind-addr>] "
            "-p <bindport> -s <host>[:<port>] [-S sourceport] ...\n", prog);
    exit(-1);
}

void add_destination(char *host) {
    char *colon;
    int dst_port;
    
    if (!port) {
        fprintf(stderr, "specify -p <port> before destination addresses\n");
        exit(-1);
    }
    colon = strrchr(host,':');
    dst_port = colon ? atoi(colon+1) : port;
    if (colon) *colon = '\0';
    
    dest.sin_family = AF_INET;
    dest.sin_port = htons(dst_port);
    
    struct hostent *h = gethostbyname(host);
    if (!h || !h->h_length) {
        fprintf(stderr, "could not resolve %s: %s\n", host, hstrerror(h_errno));
        exit(-1);
    }
    
    memcpy(&dest.sin_addr, h->h_addr, h->h_length);
    if (dest.sin_addr.s_addr == INADDR_NONE) {
        fprintf(stderr, "invalid IP address for %s\n", host);
        exit(-1);
    }
    
    if (verbose) fprintf(stderr,"repeat-to %s (%s):%d\n", host,
                         inet_ntoa(dest.sin_addr), dst_port);
    
 
}

int main(int argc, char** argv) {
    
    
    char address[234]="localhost:7001";
    
    char* n_argv[] = { "udpforaward", "-vp", "7000", "-s",address,"-S","6067",NULL};
    argv = n_argv;
    argc=7;
    
    
    prog = argv[0];
    int i, rc, sc, opt;
    
    while ( (opt = getopt(argc, argv, "v+l:p:s:S:")) != -1) {
        switch (opt) {
                case 'v': verbose++; break;
                case 'l': ip = strdup(optarg); break;
                case 'p': port = atoi(optarg); break;
                case 's': add_destination(optarg); break;
                case 'S': sourceport = atoi(optarg); break;
            default: usage(); break;
        }
    }
    
    if (!port) usage();
    
    in_addr_t listen_addr;
    if (ip) {
        if ( (listen_addr = inet_addr(ip)) == INADDR_NONE) {
            fprintf(stderr,"invalid listener IP address: %s\n", ip);
            exit(-1);
        }
    } else {
        listen_addr = htonl(INADDR_ANY);
        ip = "all-local-addresses";
    }
    if (verbose) fprintf(stderr, "local address: %s:%d\n", ip, port);
    
    /**********************************************************
     * create two IPv4/UDP sockets, for listener and repeater
     *********************************************************/
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    int rd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1 || rd == -1) { fprintf(stderr,"socket error\n"); exit(-1); }
    
    /**********************************************************
     * internet socket address structure: our address and port
     *********************************************************/
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = listen_addr;
    sin.sin_port = htons(port);
    
    /**********************************************************
     * bind socket to address and port we'd like to receive on
     *********************************************************/
    if (bind(fd, (struct sockaddr*)&sin, sizeof(sin)) == -1) {
        fprintf(stderr, "listen bind to %s:%d failed: %s\n", ip, port, strerror(errno));
        exit(-1);
    }
    
    if(sourceport!= -1)
    {
        
        struct sockaddr_in sin2;
        sin2.sin_family = AF_INET;
        sin2.sin_addr.s_addr = listen_addr;
        sin2.sin_port = htons(sourceport );
        
        if (bind(rd, (struct sockaddr*)&sin2, sizeof(sin2)) == -1) {
            fprintf(stderr, "source address bind to %s:%d failed: %s\n", ip, ntohs(sin2.sin_port) , strerror(errno));
            exit(-1);
        }else
        {
            fprintf(stderr, "source address bind to %s:%d ", ip, ntohs(sin2.sin_port));
            
        }
        

    }
    
    
    
    /**********************************************************
     * uses recvfrom to get data along with client address/port
     *********************************************************/
    do {
        struct sockaddr_in cin;
        socklen_t cin_sz = sizeof(cin);
        
        fd_set readfds;
        
        FD_ZERO(&readfds);
        FD_SET(fd,&readfds);
        FD_SET(rd,&readfds);

        

        
        select(rd+1, &readfds, NULL, NULL, NULL);
        
        if(FD_ISSET(fd, &readfds))
        {
        
        
        rc = recvfrom(fd,buf,BUFSZ,0,(struct sockaddr*)&cin,&cin_sz);
        if (rc==-1) fprintf(stderr,"recvfrom: %s\n", strerror(errno));
        else {
            int len = rc;
            if (verbose>0) fprintf(stderr,
                                   "received %d bytes from %s:%d\n", len,
                                   inet_ntoa(cin.sin_addr), (int)ntohs(cin.sin_port));
            if (verbose>1) fprintf(stderr, "%.*s\n", len, buf);

                struct sockaddr_in *d = &dest;
                if (verbose) fprintf(stderr, "sending %d bytes to %s:%d\n", len,
                                     inet_ntoa(d->sin_addr), (int)ntohs(d->sin_port));
                sc = sendto(rd, buf, len, 0, (struct sockaddr*)d, sizeof(*d));
                if (sc != len) {
                    fprintf(stderr, "sendto %s: %s\n", inet_ntoa(d->sin_addr),
                            (sc<0)?strerror(errno):"partial write");
                    exit(-1);
                
            }
            }
        }
        
        
        
        if(FD_ISSET(rd, &readfds))
        {
            
            
            rc = recvfrom(rd,buf,BUFSZ,0,(struct sockaddr*)&cin,&cin_sz);
            if (rc==-1) fprintf(stderr,"recvfrom: %s\n", strerror(errno));
            else {
                int len = rc;
                if (verbose>0) fprintf(stderr,
                                       "received %d bytes from %s:%d\n", len,
                                       inet_ntoa(cin.sin_addr), (int)ntohs(cin.sin_port));
                if (verbose>1) fprintf(stderr, "%.*s\n", len, buf);
                    struct sockaddr_in *d = &dest;
                    if (verbose) fprintf(stderr, "sending %d bytes to %s:%d\n", len,
                                         inet_ntoa(d->sin_addr), (int)ntohs(d->sin_port));
                    sc = sendto(fd, buf, len, 0, (struct sockaddr*)&sin, sizeof(sin));
                    if (sc != len) {
                        fprintf(stderr, "sendto %s: %s\n", inet_ntoa(sin.sin_addr),
                                (sc<0)?strerror(errno):"partial write");
                        exit(-1);
                    }
                
            }
        }

        
        
        
        
    } while (rc >= 0);
}