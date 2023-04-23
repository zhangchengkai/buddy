#include "buddy.h"
#define NULL ((void *)0)
int hd[16],nxt[1000000],tot=0;
int size[1000000];
void*pt[1000000],*initp,*maxp;
int mi[16];
void init(int rk,void* p){
    size[(p-initp)/4096]=rk;
    nxt[++tot]=hd[rk];
    hd[rk]=tot;
    pt[tot]=p;
}
int init_page(void *p, int pgcount){
    initp=p; maxp=p+pgcount*4096; p=p+pgcount*4096;
    for(int i=0;i<pgcount;++i) size[i]=-1;
    mi[0]=1;
    for(int i=1;i<16;i++) mi[i]=2*mi[i-1];
    for(int i=0;i<16;i++){
        if(pgcount&1){
            p=p-mi[i]*4096;
            init(i,p);
        }
        pgcount>>=1;
    }
    return OK;
}

void *alloc_pages(int rank){
    if(rank<1||rank>16) return -EINVAL;
    int rk=rank-1;
    if(!hd[rk]){
        int i=rk+1;
        while(i<16&&!hd[i]) ++i;
        if(i>=16) return -ENOSPC;
        void* p=pt[hd[i]];
        hd[i]=nxt[hd[i]];
        for(--i;i>=rk;--i){
            init(i,p+mi[i]*4096);
        }
        size[(p-initp)/4096]=rk;
        return p;
    }
    void *p=pt[hd[rk]];
    hd[rk]=nxt[hd[rk]];
    return p;
    return NULL;
}
void *Bro(void* p,int rk){
    int x=(p-initp)/4096;
    x^=(1<<rk);
    return initp+x*4096;
}
int find(void*p,int rk){
    if(pt[hd[rk]]==p){
        hd[rk]=nxt[hd[rk]];
        return 1;
    }
    for(int i=hd[rk];i;i=nxt[i]){
        if(pt[nxt[i]]==p){
            nxt[i]=nxt[nxt[i]];
            return 1;
        }
    }
    return 0;
}
int return_pages(void *p){
    if(p<initp||p>=maxp||size[(p-initp)/4096]==-1) return -EINVAL;
    int rk=size[(p-initp)/4096];
    void* bro=Bro(p,rk);
    while(rk<16 && find(bro,rk)){
        if(bro<p){void*q=p;p=bro;bro=q;}
        size[(bro-initp)/4096]=-1;
        rk++;
        bro=Bro(p,rk);
    }
    init(rk,p);
    return OK;
}

int query_ranks(void *p){
    if(size[(p-initp)/4096]!=-1) return size[(p-initp)/4096]+1;
    int ans=0,res=0;
    for(int i=(p-initp)/4096;size[i]==-1;i++) ans++;
    while(ans) res++,ans/=2;
    return res;
    return OK;
}

int query_page_counts(int rank){
    if(rank<1||rank>16) return -EINVAL;
    int rk=rank-1,ans=0;
    for(int i=hd[rk];i;i=nxt[i]) ans++;
    return ans;
    return OK;
}
