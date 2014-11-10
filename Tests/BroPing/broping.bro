@load frameworks/communication/listen

redef Communication::listen_port = 47758/tcp;
redef Communication::nodes += 
{
	["broping"] = [$host = 127.0.0.1, $events = /ping/, $connect=F, $ssl=F]
};

type PingData: record
{
	seq: count;
	src_time: time;
};

type PongData: record
{
	seq: count;
	src_time: time;
	dst_time: time;
};

event pong(pongData: PongData)
{
	print fmt("ping received, seq %d, %f at src, %f at dest, one-way: %f",
	          pongData$seq, pongData$src_time, pongData$dst_time, pongData$dst_time - pongData$src_time);
}

event ping(pingData: PingData)
{
	local pongData: PongData;

	pongData$seq      = pingData$seq;
	pongData$src_time = pingData$src_time;
	pongData$dst_time = current_time();

	event pong(pongData);
}