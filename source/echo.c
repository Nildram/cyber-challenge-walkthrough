#include <stdio.h>
#include <string.h>

#define BUFSIZE 256

void setbytes(char value, size_t bufferSizeBytes, char* buffer)
{
    for (size_t index = 0; index < bufferSizeBytes; ++index)
        buffer[index] = value;
}

void echo()
{
    char buffer[BUFSIZE];

    setbytes('\0', BUFSIZE, buffer); 
    gets(buffer);
    printf("%s %d", buffer);//, debugValue);

    return;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    while (1)
        echo();

    return 0;
}

