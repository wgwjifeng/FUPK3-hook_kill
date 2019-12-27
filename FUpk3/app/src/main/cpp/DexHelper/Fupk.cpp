//===------------------------------------------------------------*- C++ -*-===//
//
//                     Created by F8LEFT on 2018/4/4.
//                   Copyright (c) 2018. All rights reserved.
//===----------------------------------------------------------------------===//
//
//===----------------------------------------------------------------------===//

#include "Fupk.h"

#include <AndroidDef/AndroidDef.h>
#include <sys/stat.h>
#include "DexDumper.h"
#include "DexFixer.h"
#include "utils/myfile.h"
#include "utils/RWGuard.h"

const char* gIgnoreCasee[] = {
        "de.robv.android.xposed.installer",
        "f8left",
        nullptr
};

// ================ define for Fuk ==================
Fupk::Fupk(JNIEnv *env, std::string unpackRoot, jobject fupkObj)
        :mInfo(unpackRoot + "/information.json"){
    mEnv = env;
    mRoot = unpackRoot;
    mUpkObj = fupkObj;
    mIgnoreCase = gIgnoreCasee;
}

bool Fupk::unpackAll() {
    FLOGE("================ Start to dump all dex files ===============");
    mCookie.print();
    restoreLastStatus();
    FLOGE("restoreLastStatus finished.");
    RWGuard::getInstance()->reflesh();
    FLOGE("RWGuard::getInstance()->reflesh finished.");
    // now start to dump
    FLOGE("mCookie.size:%i", mCookie.size());
    for(int i = 0; i < mCookie.size(); i++) {
        FLOGE("mCookie i=%i started.", i);
        const char* name;
        auto dvmDex = mCookie.getCookieAt(i, name, mIgnoreCase);
        FLOGE("mCookie.getCookieAt finished.");
        if (dvmDex == nullptr) {
            continue;
        }
        auto sig = mCookie.getDvmMagic(dvmDex);
        FLOGE("mCookie.getDvmMagic finished.%s",sig.c_str());
        auto dumpIndex = mInfo.getCookieIndex(name, sig);
        FLOGE("mInfo.getCookieIndex finished.dumpIndex %d",dumpIndex);
        if (dumpIndex == -1) {
            // no recorded in config.json???
            FLOGE("unable to find cookie config %s", name);
            dumpIndex = -i;
        } else {
            // turn status from wait into unpack
            auto astatus=mInfo.getCookieStatus(dumpIndex);
            if (astatus == UnpackInfo::Status::Wait) {
                FLOGE("------------Dumping dex file %i %s status %d---------------", dumpIndex, name,astatus);
                mInfo.setCookieStatus(dumpIndex, UnpackInfo::Status::Unpack);
                mInfo.saveConfigFile();
            } else {
                FLOGE("------------Skipping dex file %i %s status %d-------------", dumpIndex, name,astatus);
                continue;
            }
        }

        std::stringstream ss;
        ss << mRoot << "/" << dumpIndex;
        std::string dumpFile = ss.str();
//        mkdir(dumpRoot.c_str(), 0700);


        FLOGE("=================Rebuinding dex file=================");
        DexDumper dumper(mEnv, dvmDex, mUpkObj,dumpFile);
        dumper.rebuild();
        FLOGE("===============Rebuinding dex file End================");

        auto fd = myfopen(dumpFile.c_str(), "w+");
        myfwrite(dumper.mRebuilded.c_str(), 1, dumper.mRebuilded.length(), fd);
        myfflush(fd);
        myfclose(fd);

        FLOGE("=================== Fix odex instruction==============");
        DexFixer fixer((u1 *) dumper.mRebuilded.c_str(), dumper.mRebuilded.length());
        fixer.fixAll();
        FLOGE("===================== odex fix end ===================");
        // generate
        fd = myfopen(dumpFile.c_str(), "w+");
        myfwrite(dumper.mRebuilded.c_str(), 1, dumper.mRebuilded.length(), fd);
        myfflush(fd);
        myfclose(fd);

        mInfo.setCookieStatus(dumpIndex, UnpackInfo::Status::Success);
        mInfo.saveConfigFile();
        FLOGE("===================== dump dex file end %i %s", dumpIndex, name);
    }



    FLOGE("======================== Dump end ==========================");

    return false;
}

bool Fupk::restoreLastStatus() {
    // loading unpack information(avoid re unpack if crash)
    FLOGE("Loading configure file");
    if (!mInfo.loadConfigFile()) {
        // may at the first time
        FLOGE("unable to load configure file");
    }
    FLOGE("mCookie.size:%i", mCookie.size());
    for(int i = 0; i < mCookie.size(); i++) {
        FLOGE("mCookie i=%i started.", i);
        const char* name;
        auto dvmDex = mCookie.getCookieAt(i, name, mIgnoreCase);
        FLOGE("mCookie.getCookieAt finished.");
        if (dvmDex == nullptr)
            continue;
        auto sig = mCookie.getDvmMagic(dvmDex);
        std::string temp = sig;
        FLOGE("mCookie.getDvmMagic = %s", temp.c_str());
        mInfo.addCookie(name, sig);
    }
    // turn status
    for(int i = 0; i < mInfo.getCookiesCount(); i++) {
        // the last time, the program is crash when unpacking at i(dx),
        // just ignore i(dx) at this time
        if (mInfo.getCookieStatus(i) == UnpackInfo::Status::Unpack) {
            mInfo.setCookieStatus(i, UnpackInfo::Status::Fail);
            FLOGE("mCookie UnpackInfo::Status::Fail");
        }
    }
    // if there are no more cookie to wait for unpack, just turn all failure
    // cookie into wait to try unpack at this time.
    bool retry = true;
    for(int i = 0; i < mInfo.getCookiesCount(); i++) {
        if (mInfo.getCookieStatus(i) == UnpackInfo::Status::Wait) {
            retry = false;
            break;
        }
    }
    if (retry) {
        for(int i = 0; i < mInfo.getCookiesCount(); i++) {
            if (mInfo.getCookieStatus(i) == UnpackInfo::Status::Fail) {
                mInfo.setCookieStatus(i, UnpackInfo::Status::Wait);
            }
        }
    }
    // the status may changed, just save config file again
    mInfo.saveConfigFile();
    return true;
}







