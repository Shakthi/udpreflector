//
//  main.cpp
//  udpforwarder
//
//  Created by Shakthi Prasad G S on 23/10/16.
//  Copyright © 2016 self. All rights reserved.
//

#include <iostream>
#include <string>

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
 *   udp-reflector -p 6180 -l localhost -a node1.net:2222 -b node2.net:2222
 *
 * This causes udp-reflector to listen on the local matchine (port 6180;
 * you can also bind a particular local IP address with the -l flag).
 * Whenever a UDP datagram is received from a, it is re-sent to destination b
 * (specified with the -b flag), and vice versa
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
char *ip,*prog;
int port;


int verbose;



struct sockaddr_in dest;

void usage() {
    fprintf(stderr, "usage: %s [-v] [-l <bind-addr>] "
            "-p <bindport> -s <host>[:<port>] [-S sourceport] ...\n", prog);
    exit(-1);
}




class SocketAddress
{
    struct sockaddr_in socketAddress;
    

    
    
    
    
    sockaddr_in getAddress(std::string address)
    {
        std::string::size_type colonpos=address.find(':');
        if(colonpos == std::string::npos)
        {
            std::cerr <<"Unformated address"<<address<<" host:port format expected"<<std::endl;
            exit(-1);
        }
        
        
        
        std::string host= address.substr(0,colonpos);
        std::string port= address.substr(colonpos);
        
        
        sockaddr_in dest;
        
        dest.sin_family = AF_INET;
        dest.sin_port = htons(atoi(port.c_str()));
        struct hostent *h = gethostbyname(host.c_str());
        if (!h || !h->h_length) {
            fprintf(stderr, "could not resolve %s: %s\n", host.c_str(), hstrerror(h_errno));
            exit(-1);
        }
        
        memcpy(&dest.sin_addr, h->h_addr, h->h_length);
        if (dest.sin_addr.s_addr == INADDR_NONE) {
            fprintf(stderr, "invalid IP address for %s\n", host.c_str());
            exit(-1);
        }
        
        
        if (verbose) fprintf(stderr,"repeat-to %s (%s):%d\n", host.c_str(),
                             inet_ntoa(dest.sin_addr), atoi(port.c_str()));
        
        
        return dest;
    }
    
public:
    static int fd;
    
    SocketAddress()
    {}
    SocketAddress(std::string hostport)
    {
        initialized=true;
        socketAddress = getAddress(hostport);
    }
    
    SocketAddress(sockaddr_in addr)
    {
        initialized=true;
        socketAddress = addr;
    }
    
    
    bool operator==(const SocketAddress & bAddress) const
    {
        return socketAddress.sin_addr.s_addr  == bAddress.socketAddress.sin_addr.s_addr &&
        socketAddress.sin_port == bAddress.socketAddress.sin_port;
        
        
    }


    bool initialized = false;
    
    bool Send(void * buffer,size_t len)
    {
    
        ssize_t sc = sendto(fd, buffer, len, 0, (struct sockaddr*)&socketAddress, sizeof(&socketAddress));
        if (sc != len) {
            fprintf(stderr, "sendto %s: %s\n", inet_ntoa(socketAddress.sin_addr),
                    (sc==0)?strerror(errno):"partial write");
            exit(-1);
        }
       return true;
    }
    
    static const SocketAddress ReciveAny(void * buffer,size_t & len)
    {
    
        struct sockaddr_in cin;
        socklen_t cin_sz = sizeof(cin);
        
        size_t rc = recvfrom(fd,buf,BUFSZ,0,(struct sockaddr*)&cin,&cin_sz);
        len = rc;
        return SocketAddress(cin);
    
    }


};

int SocketAddress::fd;



int main(int argc, const char** argv) {
    
    
    
    const char* n_argv[] = { "udpforaward", "-vp", "7000", "-s","localhost:7001"};
    argv = n_argv;
    argc=7;
    
    
    
    
     prog = strdup(argv[0]);
    char  opt;
    
    bool aset=false,bset=false;
    SocketAddress sa;
    SocketAddress sb;

    
    while ( (opt = getopt(argc, (char* * const )argv, "v+l:p:a:b:")) != -1) {
        switch (opt) {
                case 'v': verbose++; break;
                case 'l': ip = strdup(optarg); break;
                case 'p': port = atoi(optarg); break;
                case 'a': sa = SocketAddress(optarg);aset=true; break;
                case 'b': sb = SocketAddress(optarg);bset=true; break;
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
        ip = strdup("all-local-addresses");
    }
    if (verbose) fprintf(stderr, "local address: %s:%d\n", ip, port);
    
    /**********************************************************
     * create two IPv4/UDP sockets, for listener and repeater
     *********************************************************/
    SocketAddress::fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (SocketAddress::fd == -1 ) { fprintf(stderr,"socket error\n"); exit(-1); }
    
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
    if (bind(SocketAddress::fd, (struct sockaddr*)&sin, sizeof(sin)) == -1) {
        fprintf(stderr, "listen bind to %s:%d failed: %s\n", ip, port, strerror(errno));
        exit(-1);
    }
    
    
    
    while (true)  {
        
        /**********************************************************
         * uses recvfrom to get data along with client address/port
         *********************************************************/
        
        
        size_t len;
        SocketAddress recivedAddress = SocketAddress::ReciveAny(buf, len);
        
        
        if(sa.initialized && sb.initialized)
        {
            if(recivedAddress == sa)
            {
                sb.Send(buf, len);
            }
            
            else if(recivedAddress == sb)
            {
                sa.Send(buf, len);
            }
            else
            {
                printf("Discarding ");
            }
        }else if(sa.initialized && ! sb.initialized)
        {
            
            
            if(!(recivedAddress==sa))
            {
                sb= recivedAddress;
            
            }else
            {
                printf("Discarding  ");
            }
        
        
        }else if (!sa.initialized && ! sb.initialized)
        {
        
            sa = recivedAddress;
        
        }
        
        
        
        
    }
    
        
        
}