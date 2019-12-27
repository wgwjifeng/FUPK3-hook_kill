//===------------------------------------------------------------*- C++ -*-===//
//
//                     Created by F8LEFT on 2018/4/5.
//                   Copyright (c) 2018. All rights reserved.
//===----------------------------------------------------------------------===//
//
//===----------------------------------------------------------------------===//


#include "DexDumper.h"
#include <sstream>

#include <sys/stat.h>
#include <zconf.h>
#include "utils/myfile.h"
#include "DexHashTable.h"
#include "FupkImpl.h"
#include "ClassDefBuilder.h"
#include "utils/hookutils.h"
#include "JniInfo.h"
#include <asm/ptrace.h>

extern "C" {
#include "HookZz/include/hookzz.h"
}

using namespace FupkImpl;

#define OPTMAGIC "dey\n036\0"
#define DEXMAGIC "dex\n035\0"

#define mask 0x3ffff

uint8_t* codeitem_end(const u1** pData);
uint8_t* EncodeClassData(DexClassData *pData, int& len);

void pre_call_kill_ptr(RegState *rs, ThreadStack *threadstack, CallStack *callstack) ;
void post_call_kill_ptr(RegState *rs, ThreadStack *threadstack, CallStack *callstack) ;
// =============== DexDumper ====================

DexDumper::DexDumper(JNIEnv *env, DvmDex *dvmDex, jobject upkObj,std::string dumppathName) {
    mEnv = env;
    mDvmDex = dvmDex;
    mUpkObj = upkObj;
    mdumppathName = dumppathName;
    mcinfoarr=NULL;
}

bool DexDumper::getDexClassInfo(int num)
{
    char ss[200]={0};
    sprintf(ss,"%s.tmpcache",mdumppathName.c_str());
    FLOGE("tmpcache name %s",ss);
    auto sz=0;
    FILE *fr =fopen(ss, "rb");
    if (fr!=NULL)
    {
        fseek(fr, 0, SEEK_END);
        sz=ftell(fr);
        fseek(fr, 0, SEEK_SET);
    }


    char *buf=NULL;
    FLOGE("malloc %d",sz);

    if(sz!=0)
    {
        mcinfoarr=(DexClassInfo *)malloc(num*sizeof(DexClassInfo));
        memset(mcinfoarr,0,num*sizeof(DexClassInfo));
        buf=(char *)malloc(sz);
        myfread ( buf, 1, sz, fr);
        int i=0;
        int pos=0;
        while((pos+12+sizeof(DexClassDef))<sz)
        {
            FLOGE("read pos %d,i %d",pos,i);
            int lenc=*(int *)(buf+pos);
            pos +=4;
            int index =*(int *)(buf+pos);
            pos +=4;
            int deslen=*(int *)(buf+pos);
            pos+=4;
            FLOGE("read pos %d,i %d lenc %d index %d deslen %d",pos,i,lenc,index,deslen);
            if(lenc<=0||index<0||deslen<=0)
                break;
            if (lenc!=12+deslen+sizeof(DexClassDef))
                break;
            if((pos+deslen+sizeof(DexClassDef))>=sz)
                break;
            char classstr[1000]={0};
            memcpy(classstr,buf+pos,deslen);
            pos+=deslen;
            DexClassDef newdef;
            memcpy(&newdef,buf+pos,sizeof(DexClassDef));
            pos+=sizeof(DexClassDef);



            FLOGE("read index %d des %s",index,classstr);
            mcinfoarr[i].index=index;
            mcinfoarr[i].classstr=classstr;
            mcinfoarr[i].newDef=newdef;
            i++;
        }
    }


    if(buf!=NULL)
        free(buf);

    if (fr!=NULL)
        fclose(fr);

    return true;
}

int DexDumper::checkdesc(int num,int index,std::string des)
{
    if(mcinfoarr==NULL)
        return -1;
    if(mcinfoarr[index].classstr==des)
        return index;
    for (int i = 0; i < num; ++i) {
        if(mcinfoarr[i].classstr==des)
        {
            FLOGE("index %d not equal %s",i,des.c_str());
            return i;
        }
    }
    return -1;

}

int (*orig_kill)(__pid_t a1, int a2);
int fake_kill(__pid_t a1, int a2) {
    FLOGE("call kill");
    sleep(20);//等会再退出
    FLOGE("call end kill");
     return 0;
}

bool DexDumper::rebuild() {
    pid_t pid = getpid();
    FLOGE("current pid %d", pid);
    uint32_t lib_addr = get_lib_base(pid ,"libc.so");
    if (lib_addr>0)
    {
        FLOGE("hook libc so %x", lib_addr);
//        zpointer funt = (zpointer*)(lib_addr + 0x21958 + 0);
//        ZzBuildHook(funt, NULL, NULL, pre_call_kill_ptr, post_call_kill_ptr, false);
//        ZzEnableHook(funt);
        void *kill_ptr = (void *)kill;//跟上面一样效果，kill无论是否执行程序都会退出

        ZzBuildHook((void *)kill_ptr, (void *)fake_kill, (void **)&orig_kill, pre_call_kill_ptr, post_call_kill_ptr,false);
        ZzEnableHook((void *)kill_ptr);

    }




    // scan for basic data ---- DexFile Header
    AutoJniEnvRelease envGuard(mEnv);
    FLOGE("DexDumper::rebuild");
    jclass upkClazz = mEnv->GetObjectClass(mUpkObj);
    auto loaderObject = JniInfo::GetObjectField(mEnv, mUpkObj, "appLoader", "Ljava/lang/ClassLoader;");
    if (loaderObject == nullptr) {
        // not valid ... just kill it
        FLOGE("DexDumper::rebuild loaderObject == nullptr");
        return false;
    }
    auto self = FupkImpl::fdvmThreadSelf();
    auto tryLoadClass_method = mEnv->GetMethodID(upkClazz, "tryLoadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    Object* gLoader = FupkImpl::fdvmDecodeIndirectRef(self, loaderObject);
    mEnv->DeleteLocalRef(loaderObject);
    FLOGE("DexDumper::rebuild DeleteLocalRef");

    DexFile *pDexFile = mDvmDex->pDexFile;
    if (pDexFile->pOptHeader) {
        mymemcpy(&mDexOptHeader, pDexFile->pOptHeader, sizeof(DexOptHeader));
        mymemcpy(mDexOptHeader.magic, OPTMAGIC, sizeof(mDexOptHeader.magic));
    }
    mymemcpy(&mDexHeader, pDexFile->pHeader, sizeof(DexHeader));
    mymemcpy(mDexHeader.magic, DEXMAGIC, sizeof(mDexHeader.magic));

    FLOGE("DexDumper::rebuild before fixDexHeader");
    fixDexHeader();


    // copytofile
    DexSharedData shared;

    shared.num_class_defs = mDexHeader.classDefsSize;
    shared.total_point = mDexHeader.dataOff + mDexHeader.dataSize;
    shared.start = shared.total_point;
    shared.padding = 0;
    // All classDef and methodDefine is rebuilded, Non of the value in dex is used
    DexHashTable sHash = DexHashTable(pDexFile);
    shared.mHash = &sHash;

    // the interface reserved field is used to transport data
    gUpkInterface->reserved0 = &shared;

    FLOGE("DexDumper::rebuild before while shared.total_point %d",shared.total_point);
    while(shared.total_point & 3) {
        shared.total_point += 1;
        shared.extra.push_back(shared.padding);
    }

//    char ss[200]={0};
//    sprintf(ss,"%s.tmpcache",mdumppathName.c_str());
//    FLOGE("tmpcache name %s",ss);
//    auto sz=0;
//    FILE *fr =fopen(ss, "rb");
//    if (fr!=NULL)
//    {
//        FLOGE("fstat");
//        fseek(fr, 0, SEEK_END);
//        sz=ftell(fr);
//        fseek(fr, 0, SEEK_SET);
//    }


//    char *buf=NULL;
//    FLOGE("malloc %d",sz);
//    DexClassInfo *cinfoarr=(DexClassInfo *)malloc(shared.num_class_defs*sizeof(DexClassInfo));
//    if(sz!=0)
//    {
//        buf=(char *)malloc(sz);
//        FLOGE("openfile read");
//        fread ( buf, 1, sz, fr);
//
//
//    }



//
//    if (fr!=NULL)
//        fclose(fr);

//    getDexClassInfo(shared.num_class_defs);

//    FLOGE("openfile");
//    auto fd = fopen(ss, "wb");
//    myfwrite(dumper.mRebuilded.c_str(), 1, dumper.mRebuilded.length(), fd);
//    myfflush(fd);
//    myfclose(fd);

//rebuild 过程保存，防止class太多导致过程中断又重新开始
    FLOGE("num class def: %u", shared.num_class_defs);
    for(int i = 0; i < shared.num_class_defs; i++) {
        FLOGE("cur class: %u Total: %u", i, shared.num_class_defs);

        // try use interpret first
        auto origClassDef = dexGetClassDef(mDvmDex->pDexFile, i);

        auto descriptor = dexGetClassDescriptor(mDvmDex->pDexFile, origClassDef);
        // descriptor must look like Ljava/lang/String;, so just change into java.lang.String
        // get dot name

        std::string dotDescriptor = descriptor;
//        int x=checkdesc(shared.num_class_defs,i,dotDescriptor);
//        if (x!= -1)
//        {//不重复执行
//            FLOGE("des: %s already deal,continue.",descriptor);
//            char stri[1000]={0};
//            int dlen=strlen(descriptor);
//            int lenstri=4+4+4+dlen+sizeof(DexClassDef);
//            if(lenstri<1000)
//            {
//                memcpy(stri,&lenstri,4);
//                memcpy(stri+4,&i,4);
//                memcpy(stri+8,&dlen,4);
//                memcpy(stri+12,descriptor,dlen);
//                memcpy(stri+12+dlen,&mcinfoarr[i].newDef,sizeof(DexClassDef));
//                myfwrite(stri, 1,lenstri, fd);
//            }
//            else{
//                FLOGE("len>=1000");
//            }
//            shared.classFile.append((char*)&mcinfoarr[i].newDef, sizeof(DexClassDef));
//            continue;
//        }
        dotDescriptor = dotDescriptor.substr(1, dotDescriptor.length() - 2);
//        FLOGE("dotDescriptor: %s",dotDescriptor.c_str());
        for(char *c = (char*)dotDescriptor.c_str(); *c != '\0'; c++) {
            if (*c == '/') {
                *c = '.';
            }
        }
        ClassObject* Clazz = nullptr;
        // try load class by original loader
        if (Clazz == nullptr) {
            jstring jDotDescriptor = mEnv->NewStringUTF(dotDescriptor.c_str());
            auto jClazz = mEnv->CallObjectMethod(mUpkObj, tryLoadClass_method, jDotDescriptor);
            if (jClazz != nullptr) {
                Clazz = (ClassObject*)FupkImpl::fdvmDecodeIndirectRef(self, jClazz);
                mEnv->DeleteLocalRef(jClazz);
            } else {
                FLOGE("Class loading and init false changed into normal load");
            }
            mEnv->DeleteLocalRef(jDotDescriptor);
        }

        // just loadClassFromDex. I do not really care if the class has been inited
        // No link is needed, please invoke all valid method in it
        // if failed, just scorped into fupk loader
        if (Clazz == nullptr) {
            Clazz = FupkImpl::floadClassFromDex(mDvmDex,
                                                dexGetClassDef(mDvmDex->pDexFile, i), gLoader);
            FLOGE("after load class loadClassFromDex");
        }

        // class loaded, then use ClassObject to rebuild classDef
        auto defBuilder = ClassDefBuilder(Clazz, (DexClassDef*)origClassDef, pDexFile, &sHash);
        auto newDef = defBuilder.getClassDef();

//        FLOGE("newDef %d %d %d %d %d %x",
//                newDef->accessFlags,newDef->classIdx,newDef->accessFlags,newDef->sourceFileIdx,newDef->superclassIdx,newDef->classDataOff);

        if (newDef->classDataOff == 0) {
            FLOGE("des: %s is passed", descriptor);
            goto writeClassDef;
        } else {
            FLOGE("des %s", descriptor);
            auto newData = defBuilder.getClassData();
            if (Clazz != nullptr) {
                FLOGE("fix with dvm ClassObject");
                u4 lastIndex = 0;
                for(int i = 0; i < newData->header.directMethodsSize; i++) {
                    fixMethodByDvm(shared, &newData->directMethods[i],
                                   &defBuilder, lastIndex);
                }
                lastIndex = 0;
                for(int i = 0; i < newData->header.virtualMethodsSize; i++) {
                    fixMethodByDvm(shared, &newData->virtualMethods[i],
                                   &defBuilder, lastIndex);
                }
            } else {
                FLOGE("fix with memory classDef");

                if (newData->directMethods) {
                    for(auto j = 0; j < newData->header.directMethodsSize; j++) {
                        fixMethodByMemory(shared, &newData->directMethods[j], pDexFile);
                    }
                }
                if (newData->virtualMethods) {
                    for(auto j = 0; j < newData->header.virtualMethodsSize; j++) {
                        fixMethodByMemory(shared, &newData->virtualMethods[j], pDexFile);
                    }
                }
            }

            int class_data_len = 0;
            u1* out = EncodeClassData(newData, class_data_len);
            newDef->classDataOff = shared.total_point;
            shared.extra.append((char*)out, class_data_len);
            shared.total_point += class_data_len;
            while (shared.total_point & 3) {
                shared.extra.push_back(shared.padding);
                shared.total_point++;
            }
            delete[] out;
        }


        writeClassDef:
//        char stri[1000]={0};
//        int dlen=strlen(descriptor);
//        int lenstri=4+4+4+dlen+sizeof(DexClassDef);
//        if(lenstri<1000)
//        {
//            memcpy(stri,&lenstri,4);
//            memcpy(stri+4,&i,4);
//            memcpy(stri+8,&dlen,4);
//            memcpy(stri+12,descriptor,dlen);
//            memcpy(stri+12+dlen,newDef,sizeof(DexClassDef));
//            myfwrite(stri, 1,lenstri, fd);
//        }
//        else{
//            FLOGE("len>=1000");
//        }


//        sprintf(stri,"%d\t",i);
//        myfwrite(stri, 1,strlen(stri), fd);
//        myfwrite((char*)descriptor, 1,strlen(descriptor), fd);
//        myfwrite("\t", 1,strlen("\t"), fd);
//        myfwrite((char*)newDef, 1,sizeof(DexClassDef), fd);
//        myfwrite("\n", 1,strlen("\n"), fd);
        shared.classFile.append((char*)newDef, sizeof(DexClassDef));
    }

//    fclose(fd);
    free(mcinfoarr);
    FLOGE("end class def: %u", shared.num_class_defs);
    // the local value is not used anymore, just clear it
    gUpkInterface->reserved0 = nullptr;

    // finally, rebuilt the whold dex file
    if (pDexFile->pOptHeader != nullptr) {
        // dump optheader, no need????
        u1* optDex = (u1*) (mDexOptHeader.depsOffset + (u4)pDexFile->pOptHeader);
        shared.extra.append((char*)optDex, mDexOptHeader.optOffset - mDexOptHeader.depsOffset + mDexOptHeader.optLength);
        mDexOptHeader.optOffset = shared.total_point + mDexOptHeader.optOffset - mDexOptHeader.depsOffset + 40;
        mDexOptHeader.depsOffset = shared.total_point + 40;
    }

    // header(s)
    if (pDexFile->pOptHeader) {
        mRebuilded.append((char*)&mDexOptHeader, sizeof(DexOptHeader));
    }
    mRebuilded.append((char*)&mDexHeader, sizeof(DexHeader));
    // skipping ClassDef
    mRebuilded.append((char*)pDexFile->pStringIds, (u1*)pDexFile->pClassDefs - (u1*)pDexFile->pStringIds);
    // write rebuilded classdef
    mRebuilded.append(shared.classFile);
    // write rest data
    u1* addr = (u1*)pDexFile->baseAddr + mDexHeader.classDefsOff
               + mDexHeader.classDefsSize * sizeof(DexClassDef);
    u4 len = shared.start - (addr - pDexFile->baseAddr);
    mRebuilded.append((char*)addr, len);

    // write extra data
    mRebuilded.append(shared.extra);

    return true;
}

bool DexDumper::fixDexHeader() {
    DexFile *pDexFile = mDvmDex->pDexFile;

    mDexHeader.stringIdsOff = (u4) ((u1 *) pDexFile->pStringIds - (u1 *) pDexFile->pHeader);
    mDexHeader.typeIdsOff = (u4) ((u1 *) pDexFile->pTypeIds - (u1 *) pDexFile->pHeader);
    mDexHeader.fieldIdsOff = (u4) ((u1 *) pDexFile->pFieldIds - (u1 *) pDexFile->pHeader);
    mDexHeader.methodIdsOff = (u4) ((u1 *) pDexFile->pMethodIds - (u1 *) pDexFile->pHeader);
    mDexHeader.protoIdsOff = (u4) ((u1 *) pDexFile->pProtoIds - (u1 *) pDexFile->pHeader);
    mDexHeader.classDefsOff = (u4) ((u1 *) pDexFile->pClassDefs - (u1 *) pDexFile->pHeader);
    return true;
}

bool DexDumper::fixMethodByMemory(DexSharedData &shared, DexMethod *dexMethod,
                                  DexFile *dexFile) {
    if(dexMethod->codeOff == 0 ||
       dexMethod->accessFlags & ACC_NATIVE) {
        dexMethod->codeOff = 0;
        return false;
    }

    auto code = dexGetCode(dexFile, dexMethod);

    u1 *item = (u1 *) code;
    int code_item_len = 0;
    if (code->triesSize) {
        const u1 *handler_data = dexGetCatchHandlerData(code);
        const u1 **phandler = (const u1 **) &handler_data;
        u1 *tail = codeitem_end(phandler);
        code_item_len = (int) (tail - item);
    } else {
        code_item_len = 16 + code->insnsSize * 2;
    }

    // dump and reset dexMethod info
    dexMethod->codeOff = shared.total_point;
    shared.extra.append((char*)item, code_item_len);
    shared.total_point += code_item_len;
    while (shared.total_point & 3) {
        shared.extra.push_back(shared.padding);
        shared.total_point++;
    }
    return true;
}

bool DexDumper::fixMethodByDvm(DexSharedData &shared, DexMethod *dexMethod,
                               ClassDefBuilder* builder, u4 &lastIndex) {
    lastIndex = lastIndex + dexMethod->methodIdx;
    auto m = builder->getMethodMap(lastIndex);

    FLOGI("DexDumper::fixMethodByDvm");
    assert(m != nullptr && "Unable to fix MethodBy Dvm, this should happened");

    shared.mCurMethod = dexMethod;
    FupkImpl::fupkInvokeMethod(m);
    shared.mCurMethod = nullptr;
    return true;
}

bool fupk_ExportMethod(void *thread, Method *method) {
    DexSharedData* shared = (DexSharedData*)gUpkInterface->reserved0;
    DexMethod* dexMethod = shared->mCurMethod;
    FLOGI("fupk_ExportMethod");
    u4 ac = (method->accessFlags) & mask;
    if (method->insns == nullptr || ac & ACC_NATIVE) {
        if (ac & ACC_ABSTRACT) {
            ac = ac & ~ACC_NATIVE;
        }
        dexMethod->accessFlags = ac;
        dexMethod->codeOff = 0;
        return false;
    }

    if (ac != dexMethod->accessFlags) {
        dexMethod->accessFlags = ac;
    }
    dexMethod->codeOff = shared->total_point;
    DexCode *code = (DexCode*)((const u1*) method->insns - 16);

    u1 *item = (u1*) code;
    int code_item_len = 0;
    if (code->triesSize) {
        const u1*handler_data = dexGetCatchHandlerData(code);
        const u1 **phandler = (const u1**) &handler_data;
        u1 *tail = codeitem_end(phandler);
        code_item_len = (int)(tail - item);
    } else {
        code_item_len = 16 + code->insnsSize * 2;
    }
    shared->extra.append((char*)item, code_item_len);
    shared->total_point += code_item_len;
    while(shared->total_point & 3) {
        shared->extra.push_back(shared->padding);
        shared->total_point++;
    }
    return true;
}


// =============== helper function ==============
uint8_t* codeitem_end(const u1** pData)
{
    uint32_t num_of_list = readUnsignedLeb128(pData);
    for (;num_of_list>0;num_of_list--) {
        int32_t num_of_handlers=readSignedLeb128(pData);
        int num=num_of_handlers;
        if (num_of_handlers<=0) {
            num=-num_of_handlers;
        }
        for (; num > 0; num--) {
            readUnsignedLeb128(pData);
            readUnsignedLeb128(pData);
        }
        if (num_of_handlers<=0) {
            readUnsignedLeb128(pData);
        }
    }
    return (uint8_t*)(*pData);
}


uint8_t* EncodeClassData(DexClassData *pData, int& len)
{
    len=0;

    len+=unsignedLeb128Size(pData->header.staticFieldsSize);
    len+=unsignedLeb128Size(pData->header.instanceFieldsSize);
    len+=unsignedLeb128Size(pData->header.directMethodsSize);
    len+=unsignedLeb128Size(pData->header.virtualMethodsSize);

    if (pData->staticFields) {
        for (uint32_t i = 0; i < pData->header.staticFieldsSize; i++) {
            len+=unsignedLeb128Size(pData->staticFields[i].fieldIdx);
            len+=unsignedLeb128Size(pData->staticFields[i].accessFlags);
        }
    }

    if (pData->instanceFields) {
        for (uint32_t i = 0; i < pData->header.instanceFieldsSize; i++) {
            len+=unsignedLeb128Size(pData->instanceFields[i].fieldIdx);
            len+=unsignedLeb128Size(pData->instanceFields[i].accessFlags);
        }
    }

    if (pData->directMethods) {
        for (uint32_t i=0; i<pData->header.directMethodsSize; i++) {
            len+=unsignedLeb128Size(pData->directMethods[i].methodIdx);
            len+=unsignedLeb128Size(pData->directMethods[i].accessFlags);
            len+=unsignedLeb128Size(pData->directMethods[i].codeOff);
        }
    }

    if (pData->virtualMethods) {
        for (uint32_t i=0; i<pData->header.virtualMethodsSize; i++) {
            len+=unsignedLeb128Size(pData->virtualMethods[i].methodIdx);
            len+=unsignedLeb128Size(pData->virtualMethods[i].accessFlags);
            len+=unsignedLeb128Size(pData->virtualMethods[i].codeOff);
        }
    }

    // TODO delete []stroe
    uint8_t * store = (uint8_t *) new u1[len];

    uint8_t * result=store;

    store = writeUnsignedLeb128(store,pData->header.staticFieldsSize);
    store = writeUnsignedLeb128(store,pData->header.instanceFieldsSize);
    store = writeUnsignedLeb128(store,pData->header.directMethodsSize);
    store = writeUnsignedLeb128(store,pData->header.virtualMethodsSize);

    if (pData->staticFields) {
        for (uint32_t i = 0; i < pData->header.staticFieldsSize; i++) {
            store = writeUnsignedLeb128(store,pData->staticFields[i].fieldIdx);
            store = writeUnsignedLeb128(store,pData->staticFields[i].accessFlags);
        }
    }

    if (pData->instanceFields) {
        for (uint32_t i = 0; i < pData->header.instanceFieldsSize; i++) {
            store = writeUnsignedLeb128(store,pData->instanceFields[i].fieldIdx);
            store = writeUnsignedLeb128(store,pData->instanceFields[i].accessFlags);
        }
    }

    if (pData->directMethods) {
        for (uint32_t i=0; i<pData->header.directMethodsSize; i++) {
            store = writeUnsignedLeb128(store,pData->directMethods[i].methodIdx);
            store = writeUnsignedLeb128(store,pData->directMethods[i].accessFlags);
            store = writeUnsignedLeb128(store,pData->directMethods[i].codeOff);
        }
    }

    if (pData->virtualMethods) {
        for (uint32_t i=0; i<pData->header.virtualMethodsSize; i++) {
            store = writeUnsignedLeb128(store,pData->virtualMethods[i].methodIdx);
            store = writeUnsignedLeb128(store,pData->virtualMethods[i].accessFlags);
            store = writeUnsignedLeb128(store,pData->virtualMethods[i].codeOff);
        }
    }

    return result;
}


void pre_call_kill_ptr(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
LOGE("hooked so pre call -----------pre_call_kill_ptr,callstack %x",*threadstack);


/*
    //第五个参数
    uint32_t sp  = rs->sp;
    LOGD("sp:%#x",sp);
    LOGD("r3_len:%d",*(uint32_t*)(sp));
    STACK_SET(callstack,"sp",sp,uint32_t);
*/
}
void post_call_kill_ptr(RegState *rs, ThreadStack *threadstack, CallStack *callstack) {
    LOGE("hooked so post call -----------post_call_kill_ptr");

//    uint32_t r0 =  rs->general.regs.r0;
//    STACK_SET(callstack, "r0", r0 , uint32_t );
/*
    //第五个参数
    uint32_t sp  = rs->sp;
    LOGD("sp:%#x",sp);
    LOGD("r3_len:%d",*(uint32_t*)(sp));
    STACK_SET(callstack,"sp",sp,uint32_t);
*/
}
