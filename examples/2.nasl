for ( i = 20 ; i <= 25 ; i++)

{

sock = open_sock_tcp(i);

if ( sock)

{

display("Port no " , i , " is Open\n");

}

else

{

display("Port no " , i , " is Closed\n");

}

}
