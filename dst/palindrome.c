#include <stdio.h>
int main() {
	int n;
	scanf("%d", &n);
	int num[10] = {0};
	int index = 0;
	while(n!=0){
		num[index++] = n % 10;
		n /= 10;
	}
	index--;
	int i;
	int flag = 1;
	for(i=0;i<=index;i++){
		if(num[i] != num[index-i]){
			flag = 0;
			break;
		}
	}
	if (flag == 1) {
		printf("Y\n");
	} else {
		printf("N\n");
	}
	return 0;
}
