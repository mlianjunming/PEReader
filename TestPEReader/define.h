#pragma once
#define LOGPRINT(x,...) printf(x,__VA_ARGS__);
#define LOGPRINTW(x,...) wprintf(x,__VA_ARGS__);
#ifdef DEBUG_
#define DEBUGPRINT(x,...) if(ISDEBUG){printf("[debug] ");LOGPRINT(x,__VA_ARGS__);} 
#define DEBUGPRINTW(x,...) if(ISDEBUG){wprintf(L"[debug] ");LOGPRINTW(x,__VA_ARGS__);}
#else
#define DEBUGPRINT(x,...)
#define DEBUGPRINTW(x,...)
#endif
#define ERRORPRINT(x,...) printf("[error] ");LOGPRINT(x,__VA_ARGS__);
#define ERRORPRINTW(x,...) wprintf(L"[error] ");LOGPRINTW(x,__VA_ARGS__);
#define WARNPRINT(x,...) printf("[warn] ");LOGPRINT(x,__VA_ARGS__);
#define WARNPRINTW(x,...) wprintf(L"[warn] ");LOGPRINTW(x,__VA_ARGS__);