//#include <string.h>
//#include <pthread.h>
#include <libconfig.h>
#include "sql_thr.h"
#include "scl_thr.h"


#ifdef DEB_COREDUMP
//core_dump
#include <execinfo.h>
#include <signal.h>
#include <unistd.h>

#endif

//#define SOCK_SERVER

#ifdef SOCK_SERVER
  #include "ssrv_thr.h"
#else
  #include "scl_thr.h"
#endif

#include "sql_thr.h"
#include "calc_thr.h"
#include "main.h"

struct sdata_cfg{
    sdata_MySQL dMySQL;
    sdata_Socket dSocket;
#ifdef LINT_CFG
    long int i_tc;
  long int i_dc;
  long int i_bn;
  long int i_gbn;
  long int i_rn;
#else
    int i_dc;
    int i_tc;
    int i_bn;
    int i_gbn;
    int i_rn;
#endif
};

EC_POINT *MPoint[CountR_CL*CountC_CL];
EC_KEY* pkey;
const EC_GROUP *group;
BN_CTX *ctx = NULL;

extern unsigned char GetGPUCount();

int
count_processors(void)
{
    FILE *fp;
    char buf[512];
    int count = 0;

    fp = fopen("/proc/cpuinfo", "r");
    if (!fp)
	return -1;

    while (fgets(buf, sizeof(buf), fp)) {
	if (!strncasecmp(buf, "processor\t", 10))
	    count += 1;
    }
    fclose(fp);
//    if(count==0) count=1;
    return count;
}

int initCFG(sdata_cfg *pdata_cfg)
{
  config_t cfg; 
  config_setting_t *setting;

  config_init(&cfg);

  if(!config_read_file(&cfg, "conf.cfg"))
  {
    fprintf(stderr, "%d - %s\n", config_error_line(&cfg), config_error_text(&cfg));
    config_destroy(&cfg);
    return(EXIT_FAILURE);
  }

  setting = config_lookup(&cfg, "mysql");
  if(setting != NULL)
  {  
    const char *host, *user, *pass, *db, *table;

    config_setting_lookup_string(setting, "host", &host);
    config_setting_lookup_string(setting, "user", &user);
    config_setting_lookup_string(setting, "pass", &pass);
    config_setting_lookup_string(setting, "db", &db);
    config_setting_lookup_string(setting, "table", &table);
    config_setting_lookup_int(setting, "diff", &(pdata_cfg->dMySQL.diff));
    pdata_cfg->dMySQL.host=(char*)malloc(strlen(host)+1);
    pdata_cfg->dMySQL.user=(char*)malloc(strlen(user)+1);
    pdata_cfg->dMySQL.pass=(char*)malloc(strlen(pass)+1);
    pdata_cfg->dMySQL.db=(char*)malloc(strlen(db)+1);
    pdata_cfg->dMySQL.table=(char*)malloc(strlen(table)+1);
    strcpy(pdata_cfg->dMySQL.host, host);
    strcpy(pdata_cfg->dMySQL.user, user);
    strcpy(pdata_cfg->dMySQL.pass, pass);
    strcpy(pdata_cfg->dMySQL.db, db);
    strcpy(pdata_cfg->dMySQL.table, table);
  }

  pdata_cfg->i_tc=0;
  pdata_cfg->i_dc=0;
  pdata_cfg->i_bn=1;
  pdata_cfg->i_gbn=1;
  pdata_cfg->i_rn=3;
  setting = config_lookup(&cfg, "calc");
  if(setting != NULL)
  {  
    config_setting_lookup_int(setting, "addr", &(pdata_cfg->i_tc));
    if(pdata_cfg->i_tc==2)
    {
        config_setting_lookup_int(setting, "dc", &(pdata_cfg->i_dc));
        config_setting_lookup_int(setting, "bn", &(pdata_cfg->i_bn));
        config_setting_lookup_int(setting, "gbn", &(pdata_cfg->i_gbn));
        config_setting_lookup_int(setting, "rn", &(pdata_cfg->i_rn));
    }
  }
  setting = config_lookup(&cfg, "socket");
  if(setting != NULL)
  {  
    const char *socket_host;

    config_setting_lookup_string(setting, "host", &socket_host);
    config_setting_lookup_int(setting, "port", &(pdata_cfg->dSocket.port));
    pdata_cfg->dSocket.host=(char*)malloc(strlen(socket_host)+1);
    strcpy(pdata_cfg->dSocket.host, socket_host);
  }


}

#ifdef DEB_COREDUMP
void handler(int sig) {
  void *array[10];
  size_t size;
  char **strings;
  int j;

  FILE* fileout = NULL;
  fileout = fopen("ERR.log", "a");

  if (fileout) setbuf(fileout, NULL); // unbuffered

  // get void*'s for all entries on the stack
  size = backtrace(array, 10);

  // print out all the frames to stderr
  fprintf(fileout, "Error: signal %d:\n", sig);
//  backtrace_symbols_fd(array, size, fileout);
   strings = backtrace_symbols(array, size);
    if (strings == NULL) {
        perror("backtrace_symbols");
        exit(EXIT_FAILURE);
    }
   for (j = 0; j < size; j++)
        fprintf(fileout,"%s\n", strings[j]);

   free(strings);
  exit(1);
}
#endif

int main(int argc, char *argv[])
{
#ifdef DEB_COREDUMP
signal(SIGSEGV, handler);
#endif

  sem_t sem_sql;
  sdata_cfg Data_CFG;
  pthread_t thread_sql;
  pthread_t thread_ssrv;
  pthread_t thread_scl;
  int iCountThrCalc;

//  unsigned long ulNumberAllData=0;
  initCFG(&Data_CFG);
  char ch;
  unit_data temp_data;
  int iCountCore = count_processors();

#ifndef ONLY_SERVER
  CCD_ calc_precdata;
  unsigned char *pCD;
  if((pCD=calc_precdata.get_p_precom())!=NULL)
  {
    printf("INIT EC_table\n");
    if(Data_CFG.i_tc!=2) calc_precdata.init_ECtable(MPoint);
  }
  else
  {
    printf("predata not load - exit(0)\n");
    exit(0);
  }

  if(Data_CFG.i_tc!=2)
  {
//    init_table();
    if(iCountCore==0)
    {
	iCountThrCalc=1;
	iCountCore = 1;
    }
    else
    { 
	iCountThrCalc=iCountCore;
    }
  }
  else
  {
//    iCountThrCalc = Data_CFG.i_dc + GetGPUCount();
    iCountThrCalc = Data_CFG.i_dc + 1;
  }
  pthread_t *a_thread_calc = new pthread_t[iCountThrCalc]; 
  calc_thr_param  *a_calc_thr_p = new calc_thr_param[iCountThrCalc]; 
#endif

  int iCountOfSend=0;

  initscr();
  cbreak();
  noecho();
printw("Queue calc to sql\n");
  Q_cl<unit_data> qcl(50000);
printw("Queue sql to calc\n");
#ifdef SOCK_SERVER
  Q_cl<unit_data> qthr(500000);
#else
//client socket
  Q_cl<unit_data> qthr(400000);
#endif
  sem_init(&sem_sql, 0, 0);
  Data_CFG.dMySQL.psem_sql=&sem_sql;
  Data_CFG.dMySQL.pq=&qcl;
  Data_CFG.dMySQL.pq_thr=&qthr;

  Data_CFG.dSocket.psem_sql=&sem_sql;
  Data_CFG.dSocket.pq=&qcl;
  Data_CFG.dSocket.pq_thr=&qthr;

#ifdef SOCK_SERVER
  if(pthread_create(&thread_ssrv, NULL, f_thr_ssrv, &(Data_CFG.dSocket)))
  {
    printf("err create socket srv thr\n");
    exit(0);
  }

  if(pthread_create(&thread_sql, NULL, f_thr_sql, &(Data_CFG.dMySQL)))
  {
    printf("err create sql thr\n");
    exit(0);
  }
#else
//client socket

  if(pthread_create(&thread_scl, NULL, f_thr_scl, &(Data_CFG.dSocket)))
  {
    printf("err create socket srv thr\n");
    exit(0);
  }
#endif

#ifndef ONLY_SERVER
  if(Data_CFG.i_tc>=2)
  {    
    a_calc_thr_p[0].psem_calc = new sem_t;
    sem_init(a_calc_thr_p[0].psem_calc, 0, 0);
  }
  if(Data_CFG.i_tc==2)
  {    
    a_calc_thr_p[0].i_countcalc=0;
  }
  else
  {
    a_calc_thr_p[0].i_countcalc=iCountThrCalc*50;
  }
  while(iCountThrCalc--)
  {
      printw("Create thread calc =%d\n",iCountThrCalc);
      if(Data_CFG.i_tc==2)
      { 
#ifdef OCL_CLIENT
        a_calc_thr_p[iCountThrCalc].pcl= new CCl_(pCD);
	if(iCountThrCalc==0)
	{
	    a_calc_thr_p[iCountThrCalc].pcl->initCL(CL_DEVICE_TYPE_CPU,0,4,iCountCore*2,Data_CFG.i_rn);
//	    a_calc_thr_p[iCountThrCalc].pcl->initCL(CL_DEVICE_TYPE_CPU,0,1,iCountCore*2,Data_CFG.i_rn);
	}
	else
	{
	    a_calc_thr_p[iCountThrCalc].pcl->initCL(CL_DEVICE_TYPE_GPU,iCountThrCalc-1,Data_CFG.i_bn,Data_CFG.i_gbn,Data_CFG.i_rn);
	    a_calc_thr_p[iCountThrCalc].psem_calc=a_calc_thr_p[0].psem_calc;
	}
    printw("INITCL =%d numb=%li\n",iCountThrCalc,a_calc_thr_p[iCountThrCalc].pcl->GetDataNumber());
        a_calc_thr_p[0].i_countcalc+=a_calc_thr_p[iCountThrCalc].pcl->GetDataNumber();
#else
  printf("OCL not include in this bin\n");
  exit(0);
#endif
      }
      else
      {
	if(Data_CFG.i_tc==3)
	{
	    a_calc_thr_p[iCountThrCalc].psem_calc=a_calc_thr_p[0].psem_calc;
	}
	else
	{
          a_calc_thr_p[iCountThrCalc].psem_calc = new sem_t;
          sem_init(a_calc_thr_p[iCountThrCalc].psem_calc, 0, 0);
	}
      }
//    printw("Create thread calc =%d, semaphore=%p\n",iCountThrCalc,a_calc_thr_p[iCountThrCalc].psem_calc);
    a_calc_thr_p[iCountThrCalc].psem_sql=&sem_sql;
    a_calc_thr_p[iCountThrCalc].id_thr=iCountThrCalc;
    a_calc_thr_p[iCountThrCalc].pq=&qcl;
    a_calc_thr_p[iCountThrCalc].pq_thr=&qthr;
    switch(Data_CFG.i_tc)
    {
	case 1:
    	    a_calc_thr_p[iCountThrCalc].i_typecalc=REQ_A;
    	    pthread_create(&a_thread_calc[iCountThrCalc], NULL, f_thr_calc, &a_calc_thr_p[iCountThrCalc]);
	break;
	case 2:
    	    a_calc_thr_p[iCountThrCalc].i_typecalc=REQ_B;
	    pthread_create(&a_thread_calc[iCountThrCalc], NULL, f_thr_calc_cl, &a_calc_thr_p[iCountThrCalc]);
	break;
	case 3:
    	    a_calc_thr_p[iCountThrCalc].i_typecalc=REQ_B;
	    pthread_create(&a_thread_calc[iCountThrCalc], NULL, f_thr_calc_cache, &a_calc_thr_p[iCountThrCalc]);
	break;
	default:
	    a_calc_thr_p[iCountThrCalc].i_typecalc=REQ_W;
	    pthread_create(&a_thread_calc[iCountThrCalc], NULL, f_thr_calc, &a_calc_thr_p[iCountThrCalc]);
	break;
    }
    }
#endif
  do
  {
    ch = getch();
    if(strncasecmp(&ch, "c", 1)==0) 
    {
      printw("req sql time%d\n",time(NULL));
      sem_post(&sem_sql);
    }

  }
  while(strncasecmp(&ch, "q", 1)!=0); 
  echo();
  nocbreak();
  endwin();
  exit(1);
}