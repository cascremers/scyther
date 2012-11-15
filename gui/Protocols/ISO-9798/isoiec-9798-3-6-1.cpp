#define NAME isoiec-9798-3-6-1
#define IA A
#define IB B
#define ResA A,pk(A)
#define ResB B,pk(B)
#define TokenAB Text9,ResA,{Rb,ResA,Text5}sk(T),{Rb,Ra,B,A,Text8}sk(A)
#define TokenBA Ra,Rb,Text3,{B,Ra,Rb,A,Text2}sk(B)
#define TokenTA ResA,ResB,{Rpa,ResB,Text6}sk(T),{Rb,ResA,Text5}sk(T)

#include "isoiec-9798-3-6.template"


