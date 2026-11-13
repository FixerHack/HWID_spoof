#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <limits>
#include <cstdio>
#include <windows.h>
#include <rpc.h>
#include <wincrypt.h>
#include <iphlpapi.h>

#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "iphlpapi.lib")

// ─── Кольори ─────────────────────────────────────────────────────────────────
namespace clr {
    const char* R   = "\033[0m";
    const char* red = "\033[91m";
    const char* grn = "\033[92m";
    const char* ylw = "\033[93m";
    const char* cyn = "\033[96m";
    const char* bld = "\033[1m";
}
void EnableAnsi() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD m = 0; GetConsoleMode(h, &m);
    SetConsoleMode(h, m | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

// ─── Адміністратор ────────────────────────────────────────────────────────────
bool IsAdmin() {
    BOOL ok = FALSE; PSID sid = nullptr;
    SID_IDENTIFIER_AUTHORITY auth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&auth, 2, SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS, 0,0,0,0,0,0, &sid)) {
        CheckTokenMembership(nullptr, sid, &ok); FreeSid(sid);
    }
    return ok != FALSE;
}

// ─── Рядки ───────────────────────────────────────────────────────────────────
std::string W2A(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8,0,w.c_str(),-1,nullptr,0,nullptr,nullptr);
    std::string r(n-1,'\0');
    WideCharToMultiByte(CP_UTF8,0,w.c_str(),-1,&r[0],n,nullptr,nullptr);
    return r;
}
std::wstring A2W(const std::string& a) {
    if (a.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8,0,a.c_str(),-1,nullptr,0);
    std::wstring r(n-1,L'\0');
    MultiByteToWideChar(CP_UTF8,0,a.c_str(),-1,&r[0],n);
    return r;
}

// ─── Крипто-рандом ────────────────────────────────────────────────────────────
bool RandBytes(unsigned char* buf, DWORD len) {
    HCRYPTPROV h = 0;
    if (!CryptAcquireContextW(&h,nullptr,nullptr,PROV_RSA_FULL,CRYPT_VERIFYCONTEXT))
        return false;
    bool ok = CryptGenRandom(h,len,buf) != 0;
    CryptReleaseContext(h,0); return ok;
}
int RandIdx(int count) {
    unsigned char b; RandBytes(&b,1);
    return b % count;
}

// ─── Генератори ───────────────────────────────────────────────────────────────
std::wstring GenerateGuid() {
    UUID u; UuidCreate(&u);
    RPC_WSTR r=nullptr; UuidToStringW(&u,&r);
    std::wstring s(reinterpret_cast<wchar_t*>(r)); RpcStringFreeW(&r); return s;
}
std::wstring GenerateComputerName() {
    const wchar_t p[]=L"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const int n=static_cast<int>(sizeof(p)/sizeof(wchar_t)-1);
    unsigned char b[7]; RandBytes(b,7);
    std::wstring s=L"DESKTOP-";
    for(int i=0;i<7;++i) s+=p[b[i]%n]; return s;
}
std::wstring GenerateProductId() {
    std::wostringstream o; o<<std::setfill(L'0');
    for(int i=0;i<4;++i){
        if(i) o<<L"-";
        unsigned char b[2]; RandBytes(b,2);
        o<<std::setw(5)<<(((unsigned)(b[0]<<8|b[1]))%100000);
    } return o.str();
}
std::wstring GenerateMac() {
    unsigned char b[6]; RandBytes(b,6);
    b[0]=(b[0]&0xFE)|0x02;
    std::wostringstream o; o<<std::hex<<std::uppercase<<std::setfill(L'0');
    for(int i=0;i<6;++i) o<<std::setw(2)<<(int)b[i]; return o.str();
}
DWORD GenerateInstallDate() {
    const DWORD s=1514764800UL, r=157766400UL;
    unsigned char b[4]; RandBytes(b,4);
    DWORD v=(DWORD)b[0]<<24|(DWORD)b[1]<<16|(DWORD)b[2]<<8|b[3];
    return s+(v%r);
}

// ─── Реєстр ───────────────────────────────────────────────────────────────────
std::wstring GetRegStr(HKEY root,LPCWSTR sub,LPCWSTR name) {
    HKEY h; if(RegOpenKeyExW(root,sub,0,KEY_QUERY_VALUE,&h)!=ERROR_SUCCESS) return L"";
    DWORD sz=0; RegQueryValueExW(h,name,nullptr,nullptr,nullptr,&sz);
    if(!sz){RegCloseKey(h);return L"";}
    std::wstring r(sz/sizeof(wchar_t),L'\0');
    RegQueryValueExW(h,name,nullptr,nullptr,reinterpret_cast<LPBYTE>(&r[0]),&sz);
    RegCloseKey(h);
    while(!r.empty()&&r.back()==L'\0') r.pop_back(); return r;
}
bool SetRegStr(HKEY root,LPCWSTR sub,LPCWSTR name,const std::wstring& v) {
    HKEY h; if(RegOpenKeyExW(root,sub,0,KEY_SET_VALUE,&h)!=ERROR_SUCCESS) return false;
    LSTATUS st=RegSetValueExW(h,name,0,REG_SZ,
        reinterpret_cast<const BYTE*>(v.c_str()),
        static_cast<DWORD>((v.size()+1)*sizeof(wchar_t)));
    RegCloseKey(h); return st==ERROR_SUCCESS;
}
DWORD GetRegDword(HKEY root,LPCWSTR sub,LPCWSTR name) {
    HKEY h; if(RegOpenKeyExW(root,sub,0,KEY_QUERY_VALUE,&h)!=ERROR_SUCCESS) return 0;
    DWORD v=0,sz=sizeof(DWORD);
    RegQueryValueExW(h,name,nullptr,nullptr,reinterpret_cast<LPBYTE>(&v),&sz);
    RegCloseKey(h); return v;
}
bool SetRegDword(HKEY root,LPCWSTR sub,LPCWSTR name,DWORD v) {
    HKEY h; if(RegOpenKeyExW(root,sub,0,KEY_SET_VALUE,&h)!=ERROR_SUCCESS) return false;
    LSTATUS st=RegSetValueExW(h,name,0,REG_DWORD,
        reinterpret_cast<const BYTE*>(&v),sizeof(DWORD));
    RegCloseKey(h); return st==ERROR_SUCCESS;
}
bool DeleteRegVal(HKEY root,LPCWSTR sub,LPCWSTR name) {
    HKEY h; if(RegOpenKeyExW(root,sub,0,KEY_SET_VALUE,&h)!=ERROR_SUCCESS) return false;
    RegDeleteValueW(h,name); RegCloseKey(h); return true;
}

// ─── Timezone ─────────────────────────────────────────────────────────────────
struct TzEntry { const wchar_t* key; const char* label; };
const TzEntry TIMEZONES[] = {
    { L"UTC",                            "UTC+0   Universal" },
    { L"GMT Standard Time",              "UTC+0   London, Dublin, Lisbon" },
    { L"W. Europe Standard Time",        "UTC+1   Amsterdam, Berlin, Vienna" },
    { L"Central European Standard Time", "UTC+1   Warsaw, Prague, Budapest" },
    { L"Romance Standard Time",          "UTC+1   Paris, Madrid, Brussels" },
    { L"FLE Standard Time",              "UTC+2   Kyiv, Helsinki, Riga, Tallinn" },
    { L"GTB Standard Time",              "UTC+2   Athens, Bucharest" },
    { L"Russian Standard Time",          "UTC+3   Moscow, St. Petersburg" },
    { L"Eastern Standard Time",          "UTC-5   New York, Miami, Boston" },
    { L"Central Standard Time",          "UTC-6   Chicago, Dallas, Houston" },
    { L"Mountain Standard Time",         "UTC-7   Denver, Phoenix" },
    { L"Pacific Standard Time",          "UTC-8   Los Angeles, Seattle" },
    { L"Tokyo Standard Time",            "UTC+9   Tokyo, Seoul, Osaka" },
    { L"AUS Eastern Standard Time",      "UTC+10  Sydney, Melbourne" },
};
const int TZ_COUNT = static_cast<int>(sizeof(TIMEZONES)/sizeof(TIMEZONES[0]));

bool SetTimezone(const std::wstring& keyName) {
    std::wstring path = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones\\" + keyName;
    HKEY h;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,path.c_str(),0,KEY_QUERY_VALUE,&h) != ERROR_SUCCESS)
        return false;
    struct { LONG Bias,StandardBias,DaylightBias; SYSTEMTIME StdDate,DltDate; } tzi={};
    DWORD sz=sizeof(tzi);
    RegQueryValueExW(h,L"TZI",nullptr,nullptr,reinterpret_cast<LPBYTE>(&tzi),&sz);
    wchar_t stdN[64]={},dltN[64]={};
    sz=sizeof(stdN); RegQueryValueExW(h,L"Std",nullptr,nullptr,reinterpret_cast<LPBYTE>(stdN),&sz);
    sz=sizeof(dltN); RegQueryValueExW(h,L"Dlt",nullptr,nullptr,reinterpret_cast<LPBYTE>(dltN),&sz);
    RegCloseKey(h);

    DYNAMIC_TIME_ZONE_INFORMATION d={};
    d.Bias=tzi.Bias; d.StandardBias=tzi.StandardBias; d.DaylightBias=tzi.DaylightBias;
    d.StandardDate=tzi.StdDate; d.DaylightDate=tzi.DltDate;
    d.DynamicDaylightTimeDisabled=FALSE;
    wcsncpy(d.StandardName, stdN, 31);   d.StandardName[31]=L'\0';
    wcsncpy(d.DaylightName, dltN, 31);   d.DaylightName[31]=L'\0';
    wcsncpy(d.TimeZoneKeyName, keyName.c_str(), 127); d.TimeZoneKeyName[127]=L'\0';
    return SetDynamicTimeZoneInformation(&d) != 0;
}

// ─── Locale ───────────────────────────────────────────────────────────────────
struct LocEntry {
    const wchar_t* name;     // LocaleName
    const wchar_t* language; // sLanguage
    const wchar_t* country;  // sCountry
    const wchar_t* iCountry; // calling code (string)
    int            measure;  // 0=metric 1=imperial
    DWORD          geoId;
    const char*    label;
};
const LocEntry LOCALES[] = {
    { L"en-US", L"ENU", L"United States",  L"1",   1, 244, "en-US  English  (United States)" },
    { L"en-GB", L"ENG", L"United Kingdom", L"44",  0, 242, "en-GB  English  (United Kingdom)" },
    { L"de-DE", L"DEU", L"Germany",        L"49",  0, 94,  "de-DE  German   (Germany)" },
    { L"fr-FR", L"FRA", L"France",         L"33",  0, 84,  "fr-FR  French   (France)" },
    { L"nl-NL", L"NLD", L"Netherlands",    L"31",  0, 176, "nl-NL  Dutch    (Netherlands)" },
    { L"pl-PL", L"PLK", L"Poland",         L"48",  0, 186, "pl-PL  Polish   (Poland)" },
    { L"cs-CZ", L"CSY", L"Czech Republic", L"420", 0, 75,  "cs-CZ  Czech    (Czech Republic)" },
    { L"es-ES", L"ESP", L"Spain",          L"34",  0, 217, "es-ES  Spanish  (Spain)" },
    { L"it-IT", L"ITA", L"Italy",          L"39",  0, 118, "it-IT  Italian  (Italy)" },
    { L"uk-UA", L"UKR", L"Ukraine",        L"380", 0, 241, "uk-UA  Ukrainian(Ukraine)" },
};
const int LOC_COUNT = static_cast<int>(sizeof(LOCALES)/sizeof(LOCALES[0]));

bool SetLocale(const LocEntry& loc) {
    const wchar_t* intKey = L"Control Panel\\International";
    const wchar_t* geoKey = L"Control Panel\\International\\Geo";
    bool ok = true;
    ok &= SetRegStr(HKEY_CURRENT_USER, intKey, L"LocaleName", loc.name);
    ok &= SetRegStr(HKEY_CURRENT_USER, intKey, L"sLanguage",  loc.language);
    ok &= SetRegStr(HKEY_CURRENT_USER, intKey, L"sCountry",   loc.country);
    ok &= SetRegStr(HKEY_CURRENT_USER, intKey, L"iCountry",   loc.iCountry);
    ok &= SetRegStr(HKEY_CURRENT_USER, intKey, L"iMeasure",   loc.measure ? L"1" : L"0");
    ok &= SetRegDword(HKEY_CURRENT_USER, geoKey, L"Nation", loc.geoId);
    return ok;
}
const LocEntry* FindLocale(const std::wstring& name) {
    for(int i=0;i<LOC_COUNT;++i) if(name==LOCALES[i].name) return &LOCALES[i];
    return nullptr;
}

// ─── Screen Resolution ────────────────────────────────────────────────────────
struct ResEntry { DWORD w,h; const char* label; };
const ResEntry RESOLUTIONS[] = {
    { 1280,  720,  "1280x720   HD" },
    { 1366,  768,  "1366x768   HD" },
    { 1440,  900,  "1440x900" },
    { 1600,  900,  "1600x900" },
    { 1920, 1080,  "1920x1080  Full HD" },
    { 2560, 1080,  "2560x1080  UltraWide FHD" },
    { 2560, 1440,  "2560x1440  QHD" },
    { 3840, 2160,  "3840x2160  4K" },
};
const int RES_COUNT = static_cast<int>(sizeof(RESOLUTIONS)/sizeof(RESOLUTIONS[0]));

bool SetResolution(DWORD w, DWORD h) {
    DEVMODEW dm={}; dm.dmSize=sizeof(DEVMODEW);
    dm.dmPelsWidth=w; dm.dmPelsHeight=h;
    dm.dmFields=DM_PELSWIDTH|DM_PELSHEIGHT;
    return ChangeDisplaySettingsW(&dm, CDS_UPDATEREGISTRY) == DISP_CHANGE_SUCCESSFUL;
}
void GetCurrentResolution(DWORD& w, DWORD& h) {
    DEVMODEW dm={}; dm.dmSize=sizeof(DEVMODEW);
    if(EnumDisplaySettingsW(nullptr,ENUM_CURRENT_SETTINGS,&dm)){w=dm.dmPelsWidth;h=dm.dmPelsHeight;}
}

// ─── MAC-адреси ───────────────────────────────────────────────────────────────
struct MacEntry { std::wstring subKey, driverDesc, original, updated; };

static const wchar_t NET_KEY[]=
    L"SYSTEM\\CurrentControlSet\\Control\\Class\\"
    L"{4D36E972-E325-11CE-BFC1-08002BE10318}";

std::vector<MacEntry> EnumerateAdapters() {
    std::vector<MacEntry> r;
    HKEY hc; if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,NET_KEY,0,KEY_READ,&hc)!=ERROR_SUCCESS) return r;
    wchar_t sub[256]; DWORD idx=0;
    while(true){
        DWORD len=256;
        if(RegEnumKeyExW(hc,idx++,sub,&len,nullptr,nullptr,nullptr,nullptr)!=ERROR_SUCCESS) break;
        if(!iswdigit(sub[0])) continue;
        std::wstring fk=std::wstring(NET_KEY)+L"\\"+sub;
        std::wstring desc=GetRegStr(HKEY_LOCAL_MACHINE,fk.c_str(),L"DriverDesc");
        std::wstring inst=GetRegStr(HKEY_LOCAL_MACHINE,fk.c_str(),L"NetCfgInstanceId");
        if(desc.empty()||inst.empty()) continue;
        std::wstring lc=desc; for(auto& c:lc) c=towlower(c);
        if(lc.find(L"hyper-v")!=std::wstring::npos||lc.find(L"virtual")!=std::wstring::npos||
           lc.find(L"loopback")!=std::wstring::npos||lc.find(L"tap")!=std::wstring::npos||
           lc.find(L"wan miniport")!=std::wstring::npos) continue;
        r.push_back({fk, desc, GetRegStr(HKEY_LOCAL_MACHINE,fk.c_str(),L"NetworkAddress"), L""});
    }
    RegCloseKey(hc); return r;
}
void SpoofMacAddresses(std::vector<MacEntry>& a) {
    for(auto& m:a){
        m.updated=GenerateMac();
        bool ok=SetRegStr(HKEY_LOCAL_MACHINE,m.subKey.c_str(),L"NetworkAddress",m.updated);
        std::cout<<"  "<<(ok?clr::grn:clr::red)<<(ok?"[OK]":"[!!]")<<clr::R<<"  ";
        std::wcout<<m.driverDesc<<L" -> "<<m.updated<<L"\n";
    }
}
void RestoreMacs(const std::vector<MacEntry>& a) {
    for(const auto& m:a)
        m.original.empty()
            ? DeleteRegVal(HKEY_LOCAL_MACHINE,m.subKey.c_str(),L"NetworkAddress")
            : SetRegStr(HKEY_LOCAL_MACHINE,m.subKey.c_str(),L"NetworkAddress",m.original);
}

// ─── Дані спуфу ───────────────────────────────────────────────────────────────
struct SpoofData {
    std::wstring name, guid, productId;
    DWORD        installDate=0;
    std::vector<MacEntry> macs;
    std::wstring timezone; // TimeZoneKeyName, empty = не змінювати
    std::wstring locale;   // LocaleName,     empty = не змінювати
    DWORD        resW=0, resH=0; // 0,0 = не змінювати
};

// ─── Лог ─────────────────────────────────────────────────────────────────────
void Log(const std::string& msg) {
    std::ofstream f("spoof_log.txt",std::ios::app); if(!f) return;
    SYSTEMTIME t; GetLocalTime(&t);
    char ts[32]; std::snprintf(ts,sizeof(ts),"%04d-%02d-%02d %02d:%02d:%02d",
        t.wYear,t.wMonth,t.wDay,t.wHour,t.wMinute,t.wSecond);
    f<<"["<<ts<<"] "<<msg<<"\n";
}

// ─── Бекап ────────────────────────────────────────────────────────────────────
bool SaveBackup(const SpoofData& d,const std::string& path="backup.dat") {
    std::ofstream f(path); if(!f) return false;
    f<<"NAME="<<W2A(d.name)<<"\nGUID="<<W2A(d.guid)
     <<"\nPRODUCTID="<<W2A(d.productId)<<"\nINSTALLDATE="<<d.installDate
     <<"\nTIMEZONE="<<W2A(d.timezone)<<"\nLOCALE="<<W2A(d.locale)
     <<"\nRESW="<<d.resW<<"\nRESH="<<d.resH<<"\n";
    for(const auto& m:d.macs) f<<"MAC="<<W2A(m.subKey)<<"|"<<W2A(m.original)<<"\n";
    return true;
}
SpoofData LoadBackup(const std::string& path="backup.dat") {
    SpoofData d; std::ifstream f(path); if(!f) return d;
    std::string line;
    while(std::getline(f,line)){
        auto eq=line.find('='); if(eq==std::string::npos) continue;
        std::string k=line.substr(0,eq), v=line.substr(eq+1);
        if     (k=="NAME")        d.name=A2W(v);
        else if(k=="GUID")        d.guid=A2W(v);
        else if(k=="PRODUCTID")   d.productId=A2W(v);
        else if(k=="INSTALLDATE") d.installDate=(DWORD)std::stoul(v);
        else if(k=="TIMEZONE")    d.timezone=A2W(v);
        else if(k=="LOCALE")      d.locale=A2W(v);
        else if(k=="RESW")        d.resW=(DWORD)std::stoul(v);
        else if(k=="RESH")        d.resH=(DWORD)std::stoul(v);
        else if(k=="MAC"){ auto s=v.find('|'); if(s!=std::string::npos)
            d.macs.push_back({A2W(v.substr(0,s)),L"",A2W(v.substr(s+1)),L""});}
    }
    return d;
}

// ─── Читання / запис ──────────────────────────────────────────────────────────
SpoofData ReadCurrent() {
    SpoofData d;
    d.name=GetRegStr(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName",L"ComputerName");
    d.guid=GetRegStr(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Cryptography",L"MachineGuid");
    d.productId=GetRegStr(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",L"ProductId");
    d.installDate=GetRegDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",L"InstallDate");
    d.macs=EnumerateAdapters();
    d.timezone=GetRegStr(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation",L"TimeZoneKeyName");
    d.locale=GetRegStr(HKEY_CURRENT_USER,L"Control Panel\\International",L"LocaleName");
    GetCurrentResolution(d.resW,d.resH);
    return d;
}

bool ApplyValues(const SpoofData& d) {
    bool ok=true;
    ok&=SetRegStr(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName",L"ComputerName",d.name);
    ok&=SetRegStr(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName",L"ComputerName",d.name);
    ok&=SetRegStr(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Cryptography",L"MachineGuid",d.guid);
    ok&=SetRegStr(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",L"ProductId",d.productId);
    if(d.installDate)
        ok&=SetRegDword(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",L"InstallDate",d.installDate);
    if(!d.timezone.empty()){
        bool tz=SetTimezone(d.timezone);
        std::cout<<"  "<<(tz?clr::grn:clr::red)<<(tz?"[OK]":"[!!]")
                 <<clr::R<<"  Timezone: "<<W2A(d.timezone)<<"\n";
        ok&=tz;
    }
    if(!d.locale.empty()){
        const LocEntry* loc=FindLocale(d.locale);
        bool lc=loc?SetLocale(*loc):false;
        std::cout<<"  "<<(lc?clr::grn:clr::red)<<(lc?"[OK]":"[!!]")
                 <<clr::R<<"  Locale:   "<<W2A(d.locale)<<"\n";
        ok&=lc;
    }
    if(d.resW&&d.resH){
        bool res=SetResolution(d.resW,d.resH);
        std::cout<<"  "<<(res?clr::grn:clr::red)<<(res?"[OK]":"[!!]")
                 <<clr::R<<"  Resolution: "<<d.resW<<"x"<<d.resH;
        if(!res) std::cout<<clr::ylw<<"  (not supported by monitor)"<<clr::R;
        std::cout<<"\n";
        ok&=res;
    }
    return ok;
}

// ─── Чекер ────────────────────────────────────────────────────────────────────
void RunChecker(const SpoofData* exp=nullptr) {
    std::cout<<"\n"<<clr::bld<<clr::cyn
             <<"  +------ Registry Check ----------------------------------------+\n"
             <<clr::R;
    auto row=[&](const char* label,const std::wstring& actual,const std::wstring& expected){
        bool ok=expected.empty()?!actual.empty():(actual==expected);
        std::cout<<"  "<<(ok?clr::grn:clr::red)<<(ok?"[OK]":"[!!]")<<clr::R
                 <<"  "<<clr::bld<<label<<clr::R<<"\n       ";
        if(actual.empty()) std::cout<<clr::red<<"(read error)"<<clr::R;
        else{ std::wcout<<actual;
            if(!ok&&!expected.empty()) std::wcout<<clr::red<<L"  <- expected: "<<expected<<clr::R; }
        std::cout<<"\n";
    };
    SpoofData cur=ReadCurrent();
    row("ComputerName",      cur.name,      exp?exp->name:L"");
    row("ActiveComputerName",GetRegStr(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName",L"ComputerName"),
        exp?exp->name:L"");
    row("MachineGuid",   cur.guid,      exp?exp->guid:L"");
    row("ProductId",     cur.productId, exp?exp->productId:L"");

    // InstallDate
    { std::wostringstream o; o<<cur.installDate<<L" (Unix)";
      bool ok=exp?(cur.installDate==exp->installDate):(cur.installDate!=0);
      std::cout<<"  "<<(ok?clr::grn:clr::red)<<(ok?"[OK]":"[!!]")<<clr::R
               <<"  "<<clr::bld<<"InstallDate"<<clr::R<<"\n       ";
      std::wcout<<o.str()<<L"\n"; }

    // Timezone
    { bool ok=exp?cur.timezone==exp->timezone:!cur.timezone.empty();
      std::cout<<"  "<<(ok?clr::grn:clr::ylw)<<(ok?"[OK]":"[--]")<<clr::R
               <<"  "<<clr::bld<<"Timezone"<<clr::R<<"\n       ";
      std::wcout<<cur.timezone<<L"\n"; }

    // Locale
    { bool ok=exp?cur.locale==exp->locale:!cur.locale.empty();
      std::cout<<"  "<<(ok?clr::grn:clr::ylw)<<(ok?"[OK]":"[--]")<<clr::R
               <<"  "<<clr::bld<<"Locale (navigator.language)"<<clr::R<<"\n       ";
      std::wcout<<cur.locale<<L"\n"; }

    // Resolution
    { bool ok=exp?(cur.resW==exp->resW&&cur.resH==exp->resH):(cur.resW>0);
      std::cout<<"  "<<(ok?clr::grn:clr::ylw)<<(ok?"[OK]":"[--]")<<clr::R
               <<"  "<<clr::bld<<"Screen Resolution"<<clr::R<<"\n       "
               <<cur.resW<<"x"<<cur.resH<<"\n"; }

    // Windows API name
    { wchar_t n[MAX_COMPUTERNAME_LENGTH+1]={};DWORD l=MAX_COMPUTERNAME_LENGTH+1;
      std::wstring api=GetComputerNameW(n,&l)?std::wstring(n):L"(API error)";
      std::cout<<"\n  "<<clr::bld<<"GetComputerNameW (OS sees):"<<clr::R<<"\n       ";
      std::wcout<<api;
      if(api!=cur.name) std::cout<<clr::ylw<<"  <- differs, reboot needed"<<clr::R;
      std::cout<<"\n"; }

    // MAC
    if(!cur.macs.empty()){
        std::cout<<"\n  "<<clr::bld<<"Network Adapters (NetworkAddress):"<<clr::R<<"\n";
        for(const auto& m:cur.macs){
            std::wstring mac=GetRegStr(HKEY_LOCAL_MACHINE,m.subKey.c_str(),L"NetworkAddress");
            bool sp=!mac.empty();
            std::cout<<"  "<<(sp?clr::grn:clr::ylw)<<(sp?"[SP]":"[--]")<<clr::R<<"  ";
            std::wcout<<m.driverDesc<<L"\n       "
                      <<(sp?mac:L"original (not spoofed)")<<L"\n";
        }
        std::cout<<clr::ylw<<"  [!] MAC takes effect after adapter disable/enable\n"<<clr::R;
    }
    std::cout<<clr::bld<<clr::cyn
             <<"  +--------------------------------------------------------------+\n"
             <<clr::R<<"\n";
}

// ─── Reset to defaults ────────────────────────────────────────────────────────
// Default values used when no backup.dat is present
namespace defaults {
    const wchar_t* COMPUTER_NAME = L"DESKTOP-PC";
    const wchar_t* TIMEZONE      = L"W. Europe Standard Time"; // UTC+1
    const wchar_t* LOCALE        = L"en-US";
    const DWORD    RES_W         = 1920;
    const DWORD    RES_H         = 1080;
}

void RunReset(const std::string& backupFile = "backup.dat") {
    std::cout << "\n" << clr::bld << clr::ylw
              << "  +------ Reset to Defaults --------------------------------------+\n"
              << clr::R;

    // ── Try backup.dat first ─────────────────────────────────────────────────
    std::ifstream testFile(backupFile);
    if (testFile.good()) {
        testFile.close();
        std::cout << clr::grn << "[+] Found " << backupFile
                  << " - restoring original values...\n" << clr::R;

        SpoofData bk = LoadBackup(backupFile);
        if (!bk.name.empty() && !bk.guid.empty()) {
            std::cout << "[*] Applying backup...\n";
            ApplyValues(bk);
            RestoreMacs(bk.macs);
            Log("Reset (from backup): name=" + W2A(bk.name));
            std::cout << clr::grn << "[+] Restored from backup.\n" << clr::R;
            RunChecker(&bk);
            return;
        }
        std::cout << clr::ylw << "[!] backup.dat is invalid, falling back to defaults.\n" << clr::R;
    } else {
        std::cout << clr::ylw << "[!] No backup.dat found - resetting to Windows defaults.\n" << clr::R;
    }

    // ── No backup — reset each item to a known default ───────────────────────
    SpoofData cur = ReadCurrent();
    int ok_count = 0, fail_count = 0;

    auto report = [&](const char* label, bool ok) {
        std::cout << "  " << (ok ? clr::grn : clr::red)
                  << (ok ? "[OK]" : "[!!]") << clr::R
                  << "  " << label << "\n";
        ok ? ++ok_count : ++fail_count;
    };

    // ComputerName
    {
        bool ok = SetRegStr(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName",
            L"ComputerName", defaults::COMPUTER_NAME);
        ok &= SetRegStr(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName",
            L"ComputerName", defaults::COMPUTER_NAME);
        report("ComputerName -> DESKTOP-PC", ok);
    }

    // MachineGuid — generate a new clean one (original is unknown without backup)
    {
        std::wstring newGuid = GenerateGuid();
        bool ok = SetRegStr(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid", newGuid);
        report("MachineGuid  -> new clean GUID", ok);
    }

    // MAC addresses — delete NetworkAddress to restore hardware MAC
    {
        bool any = false;
        for (const auto& m : cur.macs) {
            DeleteRegVal(HKEY_LOCAL_MACHINE, m.subKey.c_str(), L"NetworkAddress");
            any = true;
        }
        if (any)
            report("MAC addresses -> removed (hardware MAC restored)", true);
        else
            std::cout << "  " << clr::ylw << "[--]" << clr::R
                      << "  MAC: no adapters found\n";
    }

    // Timezone
    {
        bool ok = SetTimezone(defaults::TIMEZONE);
        report("Timezone -> W. Europe Standard Time (UTC+1)", ok);
    }

    // Locale
    {
        const LocEntry* loc = FindLocale(defaults::LOCALE);
        bool ok = loc ? SetLocale(*loc) : false;
        report("Locale   -> en-US", ok);
    }

    // Resolution
    {
        bool ok = SetResolution(defaults::RES_W, defaults::RES_H);
        report("Resolution -> 1920x1080", ok);
    }

    Log("Reset to defaults (no backup)");

    std::cout << "\n  " << clr::grn << ok_count << " OK" << clr::R
              << "  " << (fail_count ? clr::red : clr::grn)
              << fail_count << " failed" << clr::R << "\n";

    if (fail_count == 0)
        std::cout << clr::grn << "[+] Reset complete.\n" << clr::R;
    else
        std::cout << clr::ylw << "[!] Some items failed - check permissions.\n" << clr::R;

    std::cout << clr::ylw
              << "[!] ComputerName: reboot to apply.\n"
              << "[!] MAC:          disable/enable adapter in Device Manager.\n"
              << "[!] Locale/TZ:    reopen browser to apply.\n"
              << clr::R;

    std::cout << clr::bld << clr::ylw
              << "  +--------------------------------------------------------------+\n"
              << clr::R << "\n";
}

// ─── UI helpers ───────────────────────────────────────────────────────────────
void WaitForEnter(const char* msg){
    std::cout<<msg;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(),'\n');
    std::cin.get();
}

// Виводить пронумерований список і зчитує вибір
// Повертає: -1 = пропустити, TZ_COUNT/LOC_COUNT/RES_COUNT = рандом, інше = індекс
int PickFromList(int count) {
    std::string line; std::getline(std::cin,line);
    if(line.empty()) return -1;
    try{
        int v=std::stoi(line);
        if(v==0) return count; // random
        if(v>=1&&v<=count) return v-1;
    } catch(...){}
    return -1;
}

void PrintUsage(){
    std::cout<<"\nUsage:\n"
             <<"  spoof.exe               interactive menu\n"
             <<"  spoof.exe --check       check current values only\n"
             <<"  spoof.exe --mode 1      stable  (no menu, all random)\n"
             <<"  spoof.exe --mode 2      temporary (no menu, all random)\n"
             <<"  spoof.exe --restore     restore from backup.dat\n"
             <<"  spoof.exe --restore <f> restore from file\n"
             <<"  spoof.exe --reset       reset to default Windows values\n\n";
}

// ─── Main ─────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    SetConsoleOutputCP(CP_UTF8);
    EnableAnsi();
    std::cout<<clr::bld<<clr::cyn
             <<"\n  +==============================+\n"
             <<"  |      HWID Spoofer v4         |\n"
             <<"+-------------------------------+\n"
             <<"  | HWID  MAC  TZ  Locale  Res  |\n"
             <<"  +==============================+\n"
             <<clr::R<<"\n";

    if(!IsAdmin()){
        std::cerr<<clr::red<<"[-] Administrator required.\n"<<clr::R
                 <<"    Right-click -> Run as administrator\n";
        WaitForEnter("\nEnter to exit...");
        return 1;
    }
    std::cout<<clr::grn<<"[+] Running as administrator.\n"<<clr::R;

    // ── Аргументи ────────────────────────────────────────────────────────────
    int         modeArg=0;
    bool        doCheck=false, doRestore=false, doReset=false;
    std::string backupFile="backup.dat";
    for(int i=1;i<argc;++i){
        std::string a=argv[i];
        if(a=="--help"||a=="-h"){PrintUsage();return 0;}
        if(a=="--check")   doCheck=true;
        if(a=="--reset")   doReset=true;
        if(a=="--restore"){doRestore=true; if(i+1<argc&&argv[i+1][0]!='-') backupFile=argv[++i];}
        if(a=="--mode"&&i+1<argc) modeArg=std::atoi(argv[++i]);
    }

    if(doCheck){ RunChecker(); WaitForEnter("Enter to exit..."); return 0; }

    if(doReset){
        RunReset(backupFile);
        WaitForEnter("Enter to exit...");
        return 0;
    }

    if(doRestore){
        SpoofData bk=LoadBackup(backupFile);
        if(bk.name.empty()||bk.guid.empty()){
            std::cerr<<clr::red<<"[-] Cannot load: "<<backupFile<<"\n"<<clr::R; return 1;}
        std::cout<<"[*] Restoring from "<<backupFile<<"...\n";
        ApplyValues(bk); RestoreMacs(bk.macs);
        Log("Restore: name="+W2A(bk.name));
        std::cout<<clr::grn<<"[+] Restored.\n"<<clr::R;
        RunChecker(&bk); WaitForEnter("Enter to exit..."); return 0;
    }

    // ── Меню вибору режиму ───────────────────────────────────────────────────
    int mode=modeArg;
    if(!mode){
        std::cout<<"\nMode:\n"
                 <<"  1. Stable    - permanent + save backup.dat\n"
                 <<"  2. Temporary - restore on Enter\n"
                 <<"  3. Check     - show current values only\n"
                 <<"  4. Reset     - restore defaults (from backup.dat or Windows defaults)\n"
                 <<"Choice: ";
        std::cin>>mode;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(),'\n');
    }
    if(mode==3){ RunChecker(); WaitForEnter("Enter to exit..."); return 0; }
    if(mode==4){ RunReset(backupFile); WaitForEnter("Enter to exit..."); return 0; }
    if(mode!=1&&mode!=2){ std::cerr<<clr::red<<"[-] Invalid.\n"<<clr::R; return 1; }

    SpoofData backup=ReadCurrent();
    if(backup.name.empty()||backup.guid.empty()){
        std::cerr<<clr::red<<"[-] Cannot read registry.\n"<<clr::R; return 1;}

    std::wcout<<L"\n"<<clr::ylw
              <<L"Current name:      "<<clr::R<<backup.name<<L"\n"
              <<clr::ylw<<L"Current GUID:      "<<clr::R<<backup.guid<<L"\n"
              <<clr::ylw<<L"Current Timezone:  "<<clr::R<<backup.timezone<<L"\n"
              <<clr::ylw<<L"Current Locale:    "<<clr::R<<backup.locale<<L"\n"
              <<clr::ylw<<L"Current Res:       "<<clr::R<<backup.resW<<L"x"<<backup.resH<<L"\n"
              <<clr::ylw<<L"Adapters found:    "<<clr::R<<backup.macs.size()<<L"\n";

    // ── Вибір timezone (інтерактивно) ─────────────────────────────────────────
    SpoofData spoofed;
    spoofed.name=GenerateComputerName();
    spoofed.guid=GenerateGuid();
    spoofed.productId=GenerateProductId();
    spoofed.installDate=GenerateInstallDate();

    if(!modeArg){
        std::cout<<"\n"<<clr::bld<<"--- Timezone ---"<<clr::R<<"\n"
                 <<"  0. Random\n";
        for(int i=0;i<TZ_COUNT;++i) printf("  %2d. %s\n",i+1,TIMEZONES[i].label);
        std::cout<<"Choice (Enter = skip): ";
        int pick=PickFromList(TZ_COUNT);
        if(pick==TZ_COUNT) spoofed.timezone=TIMEZONES[RandIdx(TZ_COUNT)].key;
        else if(pick>=0)   spoofed.timezone=TIMEZONES[pick].key;

        std::cout<<"\n"<<clr::bld<<"--- Locale (navigator.language) ---"<<clr::R<<"\n"
                 <<"  0. Random\n";
        for(int i=0;i<LOC_COUNT;++i) printf("  %2d. %s\n",i+1,LOCALES[i].label);
        std::cout<<"Choice (Enter = skip): ";
        pick=PickFromList(LOC_COUNT);
        if(pick==LOC_COUNT) spoofed.locale=LOCALES[RandIdx(LOC_COUNT)].name;
        else if(pick>=0)    spoofed.locale=LOCALES[pick].name;

        std::cout<<"\n"<<clr::bld<<"--- Screen Resolution (screen.width/height) ---"<<clr::R<<"\n"
                 <<"  0. Random\n";
        for(int i=0;i<RES_COUNT;++i) printf("  %2d. %s\n",i+1,RESOLUTIONS[i].label);
        std::cout<<"Choice (Enter = keep current): ";
        pick=PickFromList(RES_COUNT);
        if(pick==RES_COUNT){spoofed.resW=RESOLUTIONS[RandIdx(RES_COUNT)].w;
                            spoofed.resH=RESOLUTIONS[RandIdx(RES_COUNT)].h;}
        else if(pick>=0)   {spoofed.resW=RESOLUTIONS[pick].w; spoofed.resH=RESOLUTIONS[pick].h;}
    } else {
        // --mode: рандом для всього
        spoofed.timezone = TIMEZONES[RandIdx(TZ_COUNT)].key;
        spoofed.locale   = LOCALES[RandIdx(LOC_COUNT)].name;
        int ri=RandIdx(RES_COUNT); spoofed.resW=RESOLUTIONS[ri].w; spoofed.resH=RESOLUTIONS[ri].h;
    }

    std::wcout<<L"\n"<<clr::cyn
              <<L"New name:      "<<clr::R<<spoofed.name<<L"\n"
              <<clr::cyn<<L"New GUID:      "<<clr::R<<spoofed.guid<<L"\n"
              <<clr::cyn<<L"New ProductId: "<<clr::R<<spoofed.productId<<L"\n"
              <<clr::cyn<<L"New Timezone:  "<<clr::R<<spoofed.timezone<<L"\n"
              <<clr::cyn<<L"New Locale:    "<<clr::R<<spoofed.locale<<L"\n"
              <<clr::cyn<<L"New Res:       "<<clr::R<<spoofed.resW<<L"x"<<spoofed.resH<<L"\n\n";

    // ── Записуємо ─────────────────────────────────────────────────────────────
    std::cout<<"[*] Applying...\n";
    if(!ApplyValues(spoofed)){ std::cerr<<clr::red<<"[-] Registry write error.\n"<<clr::R; return 1;}

    std::cout<<"[*] Spoofing MAC addresses:\n";
    spoofed.macs=backup.macs;
    SpoofMacAddresses(spoofed.macs);

    if(mode==1){
        SaveBackup(backup);
        std::cout<<clr::grn<<"[+] Backup saved -> backup.dat\n"<<clr::R;
        Log("Spoof: name="+W2A(spoofed.name)+" tz="+W2A(spoofed.timezone)+" loc="+W2A(spoofed.locale));
    }

    std::cout<<clr::grn<<"[+] Done. Verifying...\n"<<clr::R;
    RunChecker(&spoofed);

    if(mode==2){
        WaitForEnter("Press Enter to restore and exit...");
        ApplyValues(backup); RestoreMacs(backup.macs);
        Log("Restore: name="+W2A(backup.name));
        std::cout<<clr::grn<<"[+] Restored.\n"<<clr::R;
        RunChecker(&backup);
    } else {
        std::cout<<clr::ylw
                 <<"[!] ComputerName: reboot recommended.\n"
                 <<"[!] MAC:          disable/enable adapter in Device Manager.\n"
                 <<"[!] Locale/TZ:    open new browser window to apply.\n"
                 <<clr::R;
        WaitForEnter("\nEnter to exit...");
    }
    return 0;
}
