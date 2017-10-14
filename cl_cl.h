#include <CL/cl.h>
#include "queue_calc.h"
#include "main.h"
//#include <mysql.h>


#define CountR_CL  		256*256*16
#define CountC_CL  		8 //segment of table
#define CountKEY 		2
#define LengthKEY  		32
#define LengthHASH  		20
#define LengthHASH256  		64
#define BLOCK_SIZE 		7 // count of calc for add 8 digits
#define BLOCK_SIZE_F 		4 // count of first add for  add 8 digits
//#define BLOCK_NUMBER 		1//10//  digits number  add per round max 36*7=252 - work_group<256 
//#define GLOBAL_NUMBER 		4//19//Global group number 
//#define WORK_GR_SIZE 		BLOCK_SIZE*BLOCK_NUMBER
//#define WORK_GLOBAL_GR_SIZE 	WORK_GR_SIZE*GLOBAL_NUMBER
//#define SECOND_GR_SIZE 		(BLOCK_SIZE-BLOCK_SIZE_F)*BLOCK_NUMBER*GLOBAL_NUMBER 
//#define ROUND_NUMBER 		50//24  //36
//#define DATA_NUMBER  		(ROUND_NUMBER-2)*BLOCK_NUMBER*GLOBAL_NUMBER

#define COUNT_PRECOMP_DATA   CountR_CL*LengthKEY*CountKEY*CountC_CL
#define DATA_FILE "data.bin"

#define GLOBAL_VAR 4

#define CL_MEM_SET_WR CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR
#define CL_MEM_SET_R CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR



unsigned char GetGPUCount();

class CCl_
{
private:
  cl_context context;
  cl_command_queue command_queue;

  cl_kernel multi_add_kernel;
  cl_kernel get_invers_z_kernel;
  cl_kernel get_invers_a_kernel;
  cl_kernel get_invers_b_kernel;
  cl_kernel get_hash_256_kernel;
  cl_kernel get_hash_kernel;

  cl_kernel get_test_kernel;

  cl_program program;
  cl_platform_id platform_id;
  cl_uint ret_num_platforms;

  cl_mem cmPreComp_data;
  cl_mem cmBegin_data;
  cl_mem cmHash256_data;
  cl_mem cmInd_result;
  cl_mem cmBN_data;
  cl_mem cmBN_data_l;

  unsigned char* cData;
//  unsigned char* cData_begin;
  unsigned long long* ullData_add;
  unsigned int* uiResult_ind;

//  unsigned long ulNumberAllData;

  unsigned int  ROUND_NUMBER;

  cl_device_id *ids;
  cl_uint nd;

  size_t wgs_c[1];
  size_t witems_c[1];

  size_t wgs_h[1];
  size_t witems_h[1];

  unsigned char* cData_countp;

  time_t t_start;
  time_t t_end ;

//  MYSQL *conn_s;

  cl_int err;
  void err_check( int err, const char * err_str);
//  bool save_data();
//  bool load_data();
//  bool pre_comp_data();
  void printf_dev_type(cl_device_type dt);

 public:
    CCl_(unsigned char* pD)
    {
	cData = pD;
	context = NULL;
	command_queue = NULL;
	multi_add_kernel = NULL;
        get_hash_kernel = NULL;

	program = NULL;
	platform_id = NULL;

	cmPreComp_data = NULL;
        cmBegin_data  = NULL;
	cmInd_result  = NULL;
    };
    bool initCL(cl_device_type cl_dt,unsigned int ui_number_dev,unsigned int blk_number,unsigned int gl_blk_number,unsigned int r_number);
    void Run();
    unsigned char *  GetIDS();
    unsigned int GetFreq(unsigned int ui_number_dev);

    unsigned long GetDataNumber();
    bool GetData(unsigned int ui_id_data,unit_data &temp_data,unsigned long long ull_main_count);
    bool PutData(unsigned int ui_id_data,unit_data temp_data,unsigned long long ull_main_count = 0);
    unsigned int GetNumberResult();
    unsigned int GetIndR(unsigned int id){return uiResult_ind[id+1];};
//    unsigned char * GetRData(unsigned int id) {return &cData_begin[id*LengthHASH];};
//    unsigned long long * GetRData_(unsigned int id) {return &ullData_add[id*2];};
    bool ViewData();
    bool relData();
};