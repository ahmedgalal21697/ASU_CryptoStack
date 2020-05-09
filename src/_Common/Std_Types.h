#ifndef STD_TYPES_H
#define STD_TYPES_H

#include "Platform_Types.h"

typedef uint8  Std_ReturnType;

#define STD_ON          0x01U       /* Standard ON */
#define STD_OFF         0x00U       /* Standard OFF */

#define E_OK            ((Std_ReturnType)0x00U)     // Function Return OK 
#define E_NOT_OK        ((Std_ReturnType)0x01U)     // Function Return NOT OK 

//This type shall be used to request the version of a BSW module using the <Module name>_GetVersionInfo() function
typedef struct {
	uint16 vendorID;
	uint16 moduleID;
	uint8 sw_major_version; 
	uint8 sw_minor_version; 
	uint8 sw_patch_version; 
}Std_VersionInfoType;

#define TRUE         1
#define FALSE        0

#endif //STD_TYPES_H

