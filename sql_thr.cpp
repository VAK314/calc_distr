#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curses.h>
#include <time.h>
//#include "main.h"

#include "mysql.h"
#include "sql_thr.h"
#include "main.h"

//extern sem_t sem_sql;


void * f_thr_sql(void *arg)
{
  MYSQL *conn;
  MYSQL_RES *res;
  MYSQL_ROW row;
  unit_data receive_data;
  char sql_str[230];
  char sql_str1[230];
  int iCount_end = 0;
  int iCount_end_noaddr = 0;

  unsigned int iCount_send = 0;

#ifdef DEB_SQLDUMP
  FILE* fileout = NULL;
  fileout = fopen("srv_SQL.log", "a");
  if (fileout) setbuf(fileout, NULL); // unbuffered
#endif

  while(1)
  {
    sem_wait(((sdata_MySQL *)arg)->psem_sql);
    ((sdata_MySQL *)arg)->pq->ReadQ(&receive_data);
    conn = mysql_init(NULL);
    printw("calc thr %d SQL thr %s-%s-%s ",receive_data.iId,((sdata_MySQL *)arg)->host,((sdata_MySQL *)arg)->user,((sdata_MySQL *)arg)->pass);
    if (!mysql_real_connect(conn,((sdata_MySQL *)arg)->host,((sdata_MySQL *)arg)->user, ((sdata_MySQL *)arg)->pass,((sdata_MySQL *)arg)->db, 0, NULL, 0)) {
        fprintf(stderr, "%s\n", mysql_error(conn));
	exit(1);
    }
    switch(receive_data.bCommand)
    {
    case REQ_A:
//new
#ifdef DEB_SQLDUMP
fprintf(fileout,"REQ_A\n");
#endif
      receive_data.diff=((sdata_MySQL *)arg)->diff;
      sprintf(sql_str,"call GetWorkA(1)");
      if(mysql_query(conn,sql_str))
      {
        printw("%s\n", mysql_error(conn));
      }
      else
      {
        res = mysql_use_result(conn);
        if((row = mysql_fetch_row(res)) != NULL)
        {
            strcpy(receive_data.str_nb,row[0]);
            strcpy(receive_data.str_ch,row[1]);
            strcpy(receive_data.str_hb,row[2]);
            mysql_free_result(res);
            ((sdata_MySQL *)arg)->pq_thr->WriteQ(&receive_data);
            sem_post(receive_data.psem_calc);
        }
      }
    break;
    case REQ_B:
#ifdef DEB_SQLDUMP
fprintf(fileout,"REQ_B\n");
#endif
      receive_data.diff=((sdata_MySQL *)arg)->diff;
      sprintf(sql_str,"call GetFullA(1,%d)",((unsigned int*)receive_data.str_ch)[0]); 
      if(mysql_query(conn,sql_str))
      {
        printw("%s\n", mysql_error(conn));
      }
      else
      {
	  iCount_send = 0;
          res = mysql_use_result(conn);
#ifdef DEB_SQLDUMP
fprintf(fileout,"USE buff=%d\n",((sdata_MySQL *)arg)->pq_thr->GetCountUse());
#endif
          while((row = mysql_fetch_row(res)) != NULL)
          {
#ifdef DEB_SQLDUMP
fprintf(fileout,"%s %s %d USE buff=%d\n",row[2],row[1],iCount_send,((sdata_MySQL *)arg)->pq_thr->GetCountUse());
#endif
            strcpy(receive_data.str_nb,row[0]);
            strcpy(receive_data.str_ch,row[1]);
            strcpy(receive_data.str_hb,row[2]);

            ((sdata_MySQL *)arg)->pq_thr->WriteQ(&receive_data);
            sem_post(receive_data.psem_calc);
	    iCount_send++;
          }
#ifdef DEB_SQLDUMP
fprintf(fileout,"send=%d\n",iCount_send);
#endif
          mysql_free_result(res);
      }
    break;
    case REQ_W: 
//new
#ifdef DEB_SQLDUMP
fprintf(fileout,"REQ_W\n");
#endif
      receive_data.diff=((sdata_MySQL *)arg)->diff;
      sprintf(sql_str,"call GetWork(1)");
      if(mysql_query(conn,sql_str))
      {
        printw("%s\n", mysql_error(conn));
      }
      else
      {
        res = mysql_use_result(conn);
        if((row = mysql_fetch_row(res)) != NULL)
        {
	    strcpy(receive_data.str_nb,row[0]);
            strcpy(receive_data.str_ch,row[1]);
            strcpy(receive_data.str_hb,row[2]);
            mysql_free_result(res);
            ((sdata_MySQL *)arg)->pq_thr->WriteQ(&receive_data);
            sem_post(receive_data.psem_calc);
        }
      }

    break;
    case SEND_W:
    	    sprintf(sql_str,"insert into %s set last_work=now(), id='%s', id_ch='%s', bin=unhex('%s')",((sdata_MySQL *)arg)->table,receive_data.str_nb,receive_data.str_ch,receive_data.str_hb);
    	    if(mysql_query(conn,sql_str))
    	    {
    		printw("%s\n", mysql_error(conn));
    	    }
    	    else
    	    {
    		printw("Update ch=%s\n",receive_data.str_ch);
    	    }
    break;
    case SEND_WT:
    	    sprintf(sql_str,"call WriteWT('%s','%s','%s')",receive_data.str_nb,receive_data.str_ch,receive_data.str_hb);
    	    if(mysql_query(conn,sql_str))
    	    {
    		printw("%s\n", mysql_error(conn));
    	    }
    	    else
    	    {
    		printw("Update ch=%s\n",receive_data.str_ch);
    	    }
    break;
    }
    sprintf(sql_str,"call WriteLOG('%lli','%lli','%s','%s')",receive_data.iId>>8,receive_data.iId&0xFF,receive_data.str_ch,receive_data.str_nb);
    if(mysql_query(conn,sql_str))
    {
      printw("%s\n", mysql_error(conn));
    }


    mysql_close(conn);
//    printw("connect close time=%d\n",time(NULL));
  }
}

/*
void exiterr(int exitcode)
{
fprintf(stderr, "%s\n", mysql_error(&mysql));
exit(exitcode);
}

int sql_req()
{
uint i = 0;

if (!(mysql_connect(&mysql,"192.168.2.27","user_data","work911data")))
exiterr(1);
if (mysql_select_db(&mysql,"bc")) exiterr(2);
if (mysql_query(&mysql,"SELECT name,rate FROM emp_master"))
exiterr(3);
if (!(res = mysql_store_result(&mysql))) exiterr(4);
while((row = mysql_fetch_row(res))) {
for (i=0 ; i < mysql_num_fields(res); i++)
printf("%s\n",row[i]);
}
if (!mysql_eof(res)) exiterr(5);
mysql_free_result(res);
mysql_close(&mysql);
}
*/