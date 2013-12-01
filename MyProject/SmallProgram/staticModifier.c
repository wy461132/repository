#include <stdio.h>
void fun()
{
    static int a=1;
    a++;
    printf("%d\n",a);
}
int main(int argc, char **argv)
{
    fun();
    fun();
    return 0;
}
