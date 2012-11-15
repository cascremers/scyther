#define NAME isoiec-9798-3-6-2
#define IA A
#define IB B
#define ResA A,pk(A)
#define ResB B,pk(B)
#define TokenAB Rpa,Text9,TokenTA,{Rb,Ra,B,A,Text8}sk(A)
#define TokenBA Ra,Rb,Text3,{B,Ra,Rb,A,Text2}sk(B)
#define TokenTA ResA,ResB,{Rpa,Rb,ResA,ResB,Text5}sk(T)

#include "isoiec-9798-3-6.template"


