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
//#include <pthread.h>
#include <curses.h>

#include "ssrv_thr.h"
#include "main.h"


void * f_thr_scl(void *arg){

  unit_data receive_data;
  int iSizeOfTransfer=(char*)(&receive_data.end_send_byte)-(char*)(&receive_data);

  int bytecount;
  int host_port= ((sdata_Socket *)arg)->port;
  sem_t *psem_calc;
  unsigned long long iId;
  unsigned int  iCountData;

  int i_count_con;
  unit_data temp_data;

  while(1)
  {
    sem_wait(((sdata_Socket *)arg)->psem_sql);
    ((sdata_Socket *)arg)->pq->ReadQ(&receive_data);

    struct sockaddr_in my_addr;

//    char buffer[1024];
//    int buffer_len=0;

    int hsock;
    int * p_int;
    int err;

    hsock = socket(AF_INET, SOCK_STREAM, 0);
    if(hsock == -1){
	printw("Error initializing socket %d\n",errno);
	goto FINISH;
    }
    
    p_int = (int*)malloc(sizeof(int));
    *p_int = 1;
	
    if( (setsockopt(hsock, SOL_SOCKET, SO_REUSEADDR, (char*)p_int, sizeof(int)) == -1 )||
	(setsockopt(hsock, SOL_SOCKET, SO_KEEPALIVE, (char*)p_int, sizeof(int)) == -1 ) ){
	printw("Error setting options %d\n",errno);
	free(p_int);
	goto FINISH;
    }
    free(p_int);

    my_addr.sin_family = AF_INET ;
    my_addr.sin_port = htons(host_port);
    
    memset(&(my_addr.sin_zero), 0, 8);
    my_addr.sin_addr.s_addr = inet_addr(((sdata_Socket *)arg)->host);
i_count_con = 0;
    while( connect( hsock, (struct sockaddr*)&my_addr, sizeof(my_addr)) == -1 ){
	if((err = errno) != EINPROGRESS){
	    fprintf(stderr, "connect=%d Error connecting socket %d",i_count_con, errno);
sleep(5);
	    i_count_con++;
//	    goto FINISH;
	}
    }
    if( (bytecount=send(hsock, &receive_data, iSizeOfTransfer,0))== -1){
	fprintf(stderr, "Error sending data %d\n", errno);
	goto FINISH;
    }
    printw("Sent bytes %d\n", bytecount);

    switch(receive_data.bCommand)
    {
      case REQ_W:
      case REQ_A:
        psem_calc = receive_data.psem_calc;
        iId = receive_data.iId;
        bytecount=0;
	do
	{
	    if((bytecount += recv(hsock, (char*)(&receive_data)+bytecount, iSizeOfTransfer-bytecount, 0))== -1){
   		fprintf(stderr, "Error receiving data %d\n", errno);
		goto FINISH;
    	    }
    	}
	while(bytecount<iSizeOfTransfer);
        printw("Recieved bytes %d\nReceived string\n", bytecount);

        receive_data.psem_calc = psem_calc;
        receive_data.iId = iId;
        ((sdata_Socket *)arg)->pq_thr->WriteQ(&receive_data);
        sem_post(receive_data.psem_calc);
      break;
      case REQ_B:
	iCountData = ((unsigned int*)receive_data.str_ch)[0];
        psem_calc = receive_data.psem_calc;
        iId = receive_data.iId;
	while(iCountData--)
	{
	    bytecount=0;
	    do
	    {
    		if((bytecount += recv(hsock, (char*)(&receive_data)+bytecount, iSizeOfTransfer-bytecount, 0))== -1){
		goto FINISH;
		}
    	    }
	    while(bytecount<iSizeOfTransfer);
     	    receive_data.psem_calc = psem_calc;
    	    receive_data.iId = iId;
    	    ((sdata_Socket *)arg)->pq_thr->WriteQ(&receive_data);
    	    sem_post(receive_data.psem_calc);
	};
      break;
      case SEND_W:
      case SEND_WT:
        printw("Just send work data, no wait anwser\n");
      break;
    }
    
FINISH:
    close(hsock);

  }

}
