# AutoBlockIp
This Batch Will Auto block suspicious IP from windows event log.

:warning: You need to perform this as a system administrator

## Batch Logic
1. Get suspicious IP from windows security auditing event log (eventId=`4625`)
![image](https://user-images.githubusercontent.com/18626429/196039188-5c080dee-867c-4d37-89ca-0f578927be76.png)
  * Nearly 30 minutes 
  * Exclude retry {n} times
  * Exclude white list
2. Configure the firewall through the power shell
3. Log windows event
