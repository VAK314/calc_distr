#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <netinet/in.h>
#include <resolv.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <curses.h>

#include "ssrv_thr.h"
#include "main.h"

void* SocketHandler(void*);



void * f_thr_ssrv(void *arg){
//int main(int argv, char** argc){

    struct sockaddr_in my_addr;

    int hsock;
    int i_flag = 1;
    int err;





    socklen_t addr_size = 0;
//    int* csock;
    sock_thr * p_sockthr;
    sockaddr_in sadr;
    pthread_t thread_id=0;

    
    hsock = socket(AF_INET, SOCK_STREAM, 0);
    if(hsock == -1){
	printw("Error initializing socket %d\n", errno);
	goto FINISH;
    }
    if( (setsockopt(hsock, SOL_SOCKET, SO_REUSEADDR, (char*)&i_flag, sizeof(int)) == -1 )||
	(setsockopt(hsock, SOL_SOCKET, SO_KEEPALIVE, (char*)&i_flag, sizeof(int)) == -1 ) ){
	printw("Error setting options %d\n", errno);
	goto FINISH;
    }
    my_addr.sin_family = AF_INET ;
    my_addr.sin_port = htons(((sdata_Socket *)arg)->port);
    memset(&(my_addr.sin_zero), 0, 8);
    my_addr.sin_addr.s_addr = INADDR_ANY ;
    if( bind( hsock, (sockaddr*)&my_addr, sizeof(my_addr)) == -1 ){
	fprintf(stderr,"Error binding to socket, make sure nothing else is listening on this port %d\n",errno);
	goto FINISH;
    }
    if(listen( hsock, 10) == -1 ){
	fprintf(stderr, "Error listening %d\n",errno);
	goto FINISH;
    }
    addr_size = sizeof(sockaddr_in);
    while(true){
	printw("waiting for a connection\n");
        p_sockthr = (sock_thr*)malloc(sizeof(sock_thr));

	if((p_sockthr->csock = accept( hsock, (sockaddr*)&sadr, &addr_size))!= -1){
            p_sockthr->sdata.psem_sql=((sdata_Socket *)arg)->psem_sql;
            p_sockthr->sdata.pq=((sdata_Socket *)arg)->pq;
            p_sockthr->sdata.pq_thr=((sdata_Socket *)arg)->pq_thr;
            p_sockthr->id=(((unsigned long long)sadr.sin_addr.s_addr)<<8);
	    printw("---------------------\nReceived connection from %s,%llX,%llX,%llu,%llu\n",inet_ntoa(sadr.sin_addr),sadr.sin_addr.s_addr,p_sockthr->id,sadr.sin_addr.s_addr,p_sockthr->id);
//					   Received connD402A8C000ection from 192.168.2.212,D402A8C0,D402A8C000,3556944064,9105776803(84 not print??? why???)
	    pthread_create(&thread_id,0,&SocketHandler, (void*)p_sockthr);
	    pthread_detach(thread_id);
	}
	else{
	    fprintf(stderr, "Error accepting %d\n", errno);
	}
    }
FINISH:
;
}

void* SocketHandler(void* lp){

#ifdef DEB_ETHDUMP
  FILE* fileout = NULL;
  fileout = fopen("srv_eth.log", "a");
  if (fileout) setbuf(fileout, NULL); // unbuffered
#endif

    sock_thr * p_sockthr = (sock_thr*)lp;
    unit_data receive_data;
    unsigned int  iCountData;

    int iSizeOfTransfer=(char*)(&receive_data.end_send_byte)-(char*)(&receive_data);
    int bytecount=0;

    do
    {
	if((bytecount += recv(p_sockthr->csock, (char*)(&receive_data)+bytecount, iSizeOfTransfer-bytecount, 0))== -1){
	    fprintf(stderr, "Error receiving data %d\n", errno);
	    goto FINISH;
	}
    }
    while(bytecount<iSizeOfTransfer);
    printw("Received bytes %d size unit_data=%d\n", bytecount,iSizeOfTransfer);
    sem_t sem_sock;
    receive_data.psem_calc = &sem_sock;
    sem_init(receive_data.psem_calc, 0, 0); 
    receive_data.iId=p_sockthr->id+receive_data.iId;
//receive_data.iId=IP<<8+ID;
    p_sockthr->sdata.pq->WriteQ(&receive_data);
    sem_post(p_sockthr->sdata.psem_sql);
    switch(receive_data.bCommand)
    {
      case REQ_W: 
      case REQ_A: 
        sem_wait(receive_data.psem_calc);
        if(p_sockthr->sdata.pq_thr->ReadQ(&receive_data,receive_data.iId))
        {
          printw("calc thrid=%llX receive work diff=%d %s %s %s\n",receive_data.iId,receive_data.diff,receive_data.str_ch,receive_data.str_nb,receive_data.str_hb);
          if((bytecount = send(p_sockthr->csock, &receive_data, iSizeOfTransfer, 0))== -1){
	    fprintf(stderr, "Error sending data %d\n", errno);
	    goto FINISH;
	  }
          printw("Sent bytes %d\n", bytecount);
        }
        else
        {
          printw("Not search ID\n");
        }
      break;
      case REQ_B:
	iCountData = ((unsigned int*)receive_data.str_ch)[0];
#ifdef DEB_ETHDUMP
fprintf(fileout,"iCountData=%d\n",iCountData);
#endif
	while(iCountData--)
	{
    	    sem_wait(receive_data.psem_calc);
#ifdef DEB_ETHDUMP
fprintf(fileout,"%d\n",iCountData);
#endif
    	    if(p_sockthr->sdata.pq_thr->ReadQ(&receive_data,receive_data.iId))
    	    {
        	if((bytecount = send(p_sockthr->csock, &receive_data, iSizeOfTransfer, 0))== -1){
		    goto FINISH;
		}
    	    }
    	    else
    	    {
        	printw("Not search ID\n");
    	    }
	}
      break;
      case SEND_W:
      case SEND_WT:
        printw("Just write result, no wait answer\n");
      break;
    }
FINISH:
    close(p_sockthr->csock);
    free(p_sockthr);
    return 0;
}
