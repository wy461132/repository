#include <stdio.h>
extern int a;
extern int computeSum(int num[],int n);
int main(int argc, char **argv)
{
    printf("%d\n",a);
    int num[5]={1,2,3,4,5};
    printf("The sum is: %d\n",computeSum(num,5));
    return 0;
}
