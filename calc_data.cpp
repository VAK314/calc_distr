#include <fstream>
#include <string.h>
#include <math.h>
#include <stdio.h>

#include "calc_data.h"

using namespace std;

CCD_::CCD_() 
{
    cData  = new unsigned char [COUNT_PRECOMP_DATA]; 
    cDataZ = new unsigned char [CountR_CL*8*CountC_CL];
    memset(cDataZ,0,CountR_CL*8*CountC_CL);
};

bool CCD_::save_data()
{

  ofstream outputFile(DATA_FILE,std::ofstream::binary);
  outputFile.write((char*)cData, COUNT_PRECOMP_DATA);
  outputFile.close();
  return true;

}

bool CCD_::load_data()
{

  ifstream inputFile( DATA_FILE, ios::in | ios::binary );
  if( !inputFile )
  {
    printf("File data.bin lost begin precompute data\n");
    if(!pre_comp_data()) return false;
  }
  else
  {
    printf("File data.bin found!!! Begin read data\n");
    ifstream::pos_type size = 0;
    if( inputFile.seekg(0, ios::end) )
    {
       size = inputFile.tellg();
       if(size!=COUNT_PRECOMP_DATA)
       {
          printf("wrong file size\n");
          inputFile.close();
          if(!pre_comp_data()) return false;
       }
       else
       {
         if( size && inputFile.seekg(0, std::ios::beg) )
         {
           inputFile.read((char*)cData, size);
           inputFile.close();
         }
       }
    }
  }
  return true;

}

bool CCD_::pre_comp_data()
{

  const EC_GROUP *group;
 // const EC_POINT *pgen;

  uint iCountB,ii,ii4,iStep,iShift;
  EC_KEY* pkey;
  BIGNUM *priv_key;
  BN_CTX *ctx = NULL;
  unsigned char init_str[32];

//  unsigned char sss[40];
//  int i;

    memset(cData,0,COUNT_PRECOMP_DATA);
    memset(&init_str[0], 0, 32);

    priv_key=BN_new();
    pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
    group = EC_KEY_get0_group(pkey);
    EC_POINT *pub_key = NULL;
    pub_key =EC_POINT_new(group);

    for(iCountB=0;iCountB<CountC_CL;iCountB++)
    {
      printf(" %d\n",iCountB);
      if(iCountB%2==0)
      {
        iStep=29-iCountB*5/2;
        iShift=4;
      }
      else
      {
        iStep=29-(iCountB*5-1)/2;
        iShift=0;
      }
      for(ii=1;ii<CountR_CL;ii++)
      {
        ii4=ii<<iShift;
        memcpy(&init_str[iStep],((char*)&ii4), 3);
        BN_bin2bn(init_str,32,priv_key);
        EC_POINT_mul(group,pub_key, priv_key, NULL, NULL, ctx);
        EC_POINT_make_affine(group,pub_key, ctx);
        memcpy(cData+(iCountB*CountR_CL+ii)*CountKEY*LengthKEY,pub_key->X.d,LengthKEY);
	memcpy(cData+((iCountB*CountR_CL+ii)*CountKEY+1)*LengthKEY,pub_key->Y.d,LengthKEY);
      }
      memset(&init_str[iStep],0,3);
    }
    BN_free(priv_key);
    printf("end of prepeare datat ");
    if(save_data()) return true;
    return false;
}


void CCD_::init_ECtable(EC_POINT ** MPoint)
{
  unsigned long int ii,uli_CountR_CL=CountR_CL;
//i
  pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
  group = EC_KEY_get0_group(pkey);

  for(ii=0;ii<(CountR_CL*CountC_CL);ii++)
  {
    MPoint[ii] =EC_POINT_new(group);
    if(ii%uli_CountR_CL==0)
    {
	MPoint[ii]->X.top = 0;
	MPoint[ii]->Y.top = 0;
	MPoint[ii]->Z.top = 0;
	MPoint[ii]->Z_is_one=0;
    }
    else
    {
        MPoint[ii]->X.d = (BN_ULONG*)(cData+ii*CountKEY*LengthKEY);
	MPoint[ii]->Y.d = (BN_ULONG*)(cData+(ii*CountKEY+1)*LengthKEY);
	MPoint[ii]->Z.d = (BN_ULONG*)(cDataZ+ii*8);
	MPoint[ii]->X.top = LengthKEY/8;
	MPoint[ii]->Y.top = LengthKEY/8;
	MPoint[ii]->Z.top = 1;
	MPoint[ii]->Z_is_one=1;
        MPoint[ii]->Z.d[0]=0x00000001000003D1;
    }
  }
}
