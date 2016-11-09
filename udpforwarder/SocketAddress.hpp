//
//  SocketAddress.hpp
//  udpforwarder
//
//  Created by Shakthi Prasad G S on 10/11/16.
//  Copyright © 2016 self. All rights reserved.
//

#ifndef SocketAddress_hpp
#define SocketAddress_hpp

#include <stdio.h>


extern int verbose;
#define BUFSZ 2000


class SocketAddress
{
    struct sockaddr_in socketAddress;
    
    
    
    
    
    
    sockaddr_in getAddress(std::string address)
    {
        std::string::size_type colonpos=address.find(':');
        
        if(colonpos == std::string::npos){
            
            std::cerr <<"Unformated address"<<address<<" host:port format expected"<<std::endl;
            exit(-1);
        }
        
        
        
        std::string host= address.substr(0,colonpos);
        std::string port= address.substr(colonpos+1);
        
        
        sockaddr_in dest;
        
        dest.sin_family = AF_INET;
        dest.sin_port = htons(atoi(port.c_str()));
        struct hostent *h = gethostbyname(host.c_str());
        if (!h || !h->h_length) {
            std::cerr<< "could not resolve "<<host<<":"<< hstrerror(h_errno)<<std::endl;
            exit(-1);
        }
        
        memcpy(&dest.sin_addr, h->h_addr, h->h_length);
        if (dest.sin_addr.s_addr == INADDR_NONE) {
            std::cerr<< "invalid IP address for "<<host<<std::endl;
            exit(-1);
        }
        
        
               
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
    
    const std::string  to_string()
    {
        std::string address =inet_ntoa(socketAddress.sin_addr);
        address+=":";
        address+=std::to_string(ntohs(socketAddress.sin_port) );
        
        return address;
    }
    
    
    
    bool Send(void * buffer,size_t len)
    {
        
        ssize_t sc = sendto(fd, buffer, len, 0, (struct sockaddr*)&socketAddress, sizeof(&socketAddress));
        
        if (sc != len) {
            std::cerr<< "sendto " << inet_ntoa(socketAddress.sin_addr)<<((sc==0)?strerror(errno):"partial write");
            exit(-1);
        }
        
        
        if(verbose>0)
            std::cerr<< "sent " <<len<<" bytes to "<<to_string()<<std::endl;
        
        return true;
    }
    
    
    
    
    static const SocketAddress ReciveAny(void * buffer,size_t & len)
    {
        
        
        struct sockaddr_in cin;
        socklen_t cin_sz = sizeof(cin);
        
        size_t rc = recvfrom(fd,buffer,BUFSZ,0,(struct sockaddr*)&cin,&cin_sz);
        len = rc;
        SocketAddress sa(cin);
        
        
        if(verbose>0)
            std::cerr<< "recieved "<<rc<<" bytes from " <<sa.to_string()<<std::endl;
        
        
        
        return sa;
        
    }
    
    
};



#endif /* SocketAddress_hpp */
