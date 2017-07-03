#include <stdio.h>
int main()
{
    int first,second,next,i,n;
    first=0;
    second=1;
    n=5;
    printf("\n%d\n%d",first,second);       
    for(i=0;i<n;i++)
    {
        next=first+second;//sum of numbers
        first=second;
        second=next;
        printf("\n%d",next);
    }
    return 0;
}  
