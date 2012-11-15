#define NAME isoiec-9798-3-7-2
#define IA A
#define IB B
#define ResA A,pk(A)
#define ResB B,pk(B)
#define TokenAB Rpa,Text7,TokenTA,{Rb,Ra,B,A,Text6}sk(A)
#define TokenBA Ra,Rb,Text9,{Ra,Rb,A,B,Text8}sk(B)
#define TokenTA ResA,ResB,{Rpa,Rb,ResA,ResB,Text3}sk(T)

#include "isoiec-9798-3-7.template"


