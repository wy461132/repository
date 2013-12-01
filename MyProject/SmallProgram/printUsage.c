#include <stdio.h>
#include <getopt.h>

void printUsage(char *argv0)
{
    fprintf(stderr,"Usage: %s [option]\n",argv0);
    fprintf(stderr,"\t-v or --version\t\tThe version of the TSS you would like to test.\n");
}

struct option long_option[]={
    {"narg n",1,NULL,'n'},
    {"barg b",1,NULL,'b'},
    {"larg l",1,NULL,'l'},
    {0,0,0,0},
};
/*
int main(int argc,char **argv)
{
    printUsage("Bind");
    return 0;
}
*/
int main(int argc,char **argv)
{
    int c;
    char *opt_arg;
    char* const short_options="n:b:l:";
    while((c=getopt_long(argc,argv,short_options,long_option,NULL))!=-1)
    {
        switch(c)
        {
            case 'n':
                opt_arg=optarg;
                printf("%s\n",opt_arg);
                break;
            case 'b':
                opt_arg=optarg;
                printf("%s\n",opt_arg);
                break;
            case 'l':
                opt_arg=optarg;
                printf("%s\n",opt_arg);
        }
    }
    return 0;
}
