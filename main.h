#include <semaphore.h>
#include <curses.h>
//#include <stdio.h>
//#include <stdlib.h>
//#include <time.h>


#ifndef MAIN_H
#define MAIN_H

struct unit_data
{
    unsigned long long iId;
    char bCommand;
    unsigned char diff;
    char str_ch[20];
    char str_nb[20];
    char str_hb[41];
    char end_send_byte;
    sem_t *psem_calc;
};

#define REQ_W  1
#define SEND_W 2
#define REQ_A  3
#define REQ_B  4
#define SEND_WT 5

#endif