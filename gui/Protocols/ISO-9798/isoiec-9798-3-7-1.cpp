#define NAME isoiec-9798-3-7-1
#define IA A
#define IB B
#define ResA A,pk(A)
#define ResB B,pk(B)
#define TokenAB Text7,Ra,ResA,{Rb,ResA,Text3}sk(T),{Rb,Ra,B,A,Text6}sk(A)
#define TokenBA Ra,Rb,Text9,{A,Ra,Rb,B,Text8}sk(B)
#define TokenTA ResA,ResB,{Rpa,ResB,Text4}sk(T),{Rb,ResA,Text3}sk(T)

#include "isoiec-9798-3-7.template"


