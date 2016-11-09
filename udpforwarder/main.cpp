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
#include <poll.h>

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


#include "SocketAddress.hpp"


#define BUFSZ 2000
char buf[BUFSZ];
char *ip,*prog;
int port;


int verbose;



struct sockaddr_in dest;

void usage() {
    std::cerr<<"usage: %s [-v] [-l <bind-addr>] -p <bindport> -s <host>[:<port>] [-S sourceport] ...\n";
    exit(-1);
}


int SocketAddress::fd;





int main(int argc, const char** argv) {
    
    if(argc<2)
    {
    
#if CLIENT
        
        const char* m_argv[] = { "udpforaward", "-vp", "7001", "-l","127.0.0.1","-1","-b","127.0.0.1:50001"};
    argv = m_argv;
#else
        const char* n_argv[] = { "udpforaward", "-vp", "6008", "-l","127.0.0.1","-a",
            "127.0.0.1:60001","-B","127.0.0.1:7001"};

    argv = n_argv;
#endif
        
    argc=9;
    
    }
    
    
    prog = strdup(argv[0]);
    char  opt;
    
    SocketAddress sa;
    SocketAddress sb;

    
    bool connecta=false,connectb=false;
    
    bool revieveb=false,recievea=false;

    
    
    
    while ( (opt = getopt(argc, (char* * const )argv, "v+l:p:a:b:A:B:12")) != -1) {
        switch (opt) {
                case 'v': verbose++; break;
                case 'l': ip = strdup(optarg); break;
                case 'p': port = atoi(optarg); break;
                case 'a': sa = SocketAddress(optarg); break;
                case 'b': sb = SocketAddress(optarg); break;
                
                case 'A': sa = SocketAddress(optarg); connecta=true;break;
                case 'B': sb = SocketAddress(optarg); connectb=true;break;
                case '1':  recievea=true;break;
                case '2':  revieveb=true;break;
                
            default: usage(); break;
        }
    }
    
    
    
    
    if (!port) usage();
    
    in_addr_t listen_addr;
    if (ip) {
        if ( (listen_addr = inet_addr(ip)) == INADDR_NONE) {
            std::cerr<<"invalid listener IP address "<<ip<<std::endl;
            exit(-1);
        }
    } else {
        listen_addr = htonl(INADDR_ANY);
        ip = strdup("all-local-addresses");
    }
    if (verbose)
        std::cerr<<"listening address: "<<ip<<":"<<port<<std::endl;
    
    
    /**********************************************************
     * create two IPv4/UDP sockets, for listener and repeater
     *********************************************************/
    SocketAddress::fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (SocketAddress::fd == -1 ) { std::cerr<<"socket error"<<std::endl; exit(-1);}
    
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
        std::cerr<<"listen bind to "<<ip<<":"<<port<<" failed with error :"<<strerror(errno)<<std::endl;
        exit(-1);
    }
    
    
    
    
    while (true)  {
        
        /**********************************************************
         * uses recvfrom to get data along with client address/port
         *********************************************************/
        int random = rand();
        
        if(sa.initialized && connecta)
        {
            std::string testConnection="testConnection" + std::to_string(random);
            if(verbose>0)
                std::cerr<<"testConnection to:"<< sa.to_string()<<std::endl;
            
            sa.Send((void*)testConnection.c_str(), testConnection.length());
            
            
        }
        
        if (sb.initialized && connectb)
        {
            std::string testConnection="testConnection" + std::to_string(random);
            
            if(verbose>0)
                std::cerr<<"testConnection to:"<< sb.to_string()<<std::endl;
            
            
            sb.Send((void*)testConnection.c_str(), testConnection.length());
        }
        
        
        
        if(connectb||connecta)
        {
            struct pollfd pfdfd;
            int ret;
            
            pfdfd.fd = SocketAddress::fd; // your socket handler
            pfdfd.events = POLLIN;
            ret = poll(&pfdfd, 1, 1000); // 1 second for timeout
            
            if(ret == 0 || ret ==-1)
                continue;
        }
        
        
        
        
        
        size_t len;
        SocketAddress recivedAddress = SocketAddress::ReciveAny(buf, len);
        
        
        if(sa.initialized && sb.initialized)
        {
            if(recivedAddress == sa )
            {
                if(!recievea && !connecta)
                sb.Send(buf, len);
            }
            
            else if(recivedAddress == sb)
            {
                if(!revieveb && !connectb)

                sa.Send(buf, len);
            }
            else
            {
                std::cerr<<"Discarding "<<len<<"bytes from"<<recivedAddress.to_string()<<std::endl;
            }
        }else if(sa.initialized && ! sb.initialized)
        {
            
            
            if(!(recivedAddress==sa))
            {
                sb= recivedAddress;
                
                if(!revieveb)
                    sa.Send(buf, len);
              

            
            }else
            {
                std::cerr<<"Discarding "<<len<<"bytes from"<<recivedAddress.to_string()<<std::endl;
            }
        
        
        }else if(!sa.initialized &&  sb.initialized){
        
            
            if(!(recivedAddress==sb))
            {
                sa= recivedAddress;
                
                if(!recievea)
                    sb.Send(buf, len);
                
                
            }else
            {
                std::cerr<<"Discarding "<<len<<"bytes from"<<recivedAddress.to_string()<<std::endl;
            }

        
        }
        
        
        else if (!sa.initialized && ! sb.initialized)
        {
        
            sa = recivedAddress;
        
        }
        
        
        
        if(recivedAddress == sa && connecta )
        {
            std::string testConnection=std::string(buf,len);
            if(testConnection=="testConnection")
            {
                connecta = false;
                std::cerr<< "connection scuccedded  to "<<sa.to_string();
                
            }
            
            
        }
        
        if (recivedAddress == sb && connectb)
        {
            std::string testConnection1="testConnection"+std::to_string(random);

            std::string testConnection=std::string(buf,len);
            if(testConnection==testConnection1)
            {
               std::cerr<< "connection scuccedded  to "<<sb.to_string();
                connectb =false;
            }
            
        }

        
        if(recivedAddress == sa && recievea )
        {
            std::string testConnection=std::string(buf,len);
            if(testConnection.find("testConnection")==std::string::npos)
                exit(-1);
            else
                recivedAddress.Send((void*)testConnection.c_str(), testConnection.length());
            
            
        }
        
        if (recivedAddress == sb && revieveb )
        {
            std::string testConnection=std::string(buf,len);
            if(testConnection.find("testConnection")==std::string::npos)
                exit(-1);
            else
                recivedAddress.Send((void*)testConnection.c_str(), testConnection.length());

            
        }

        
    }
    
        
        
}