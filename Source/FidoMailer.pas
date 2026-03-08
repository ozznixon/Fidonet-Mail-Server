{ ==========================================================================
  FidoMailer.pas — Main mailer engine
  Orchestrates: session negotiation, file transfer, toss, poll queue
  Uses DXSock 6 for all network I/O
  ========================================================================== }
unit FidoMailer;

{$MODE DELPHI}

interface

uses
  SysUtils, Classes,
  FidoNet, FidoPkt, FidoSession, FidoZModem, FidoBark,
  FidoNodelist, FidoToss, FidoDXSock,
  DXSock6, dxutil_environment, dxsock_genericserver;

type
  TLogLevel = (llDebug, llInfo, llWarn, llError);

  TMailerLog = procedure(Level: TLogLevel;
    const Msg: string) of object;

  TPollEntry = record
    Addr     : TFidoAddr;
    Phone    : string;
    Password : string;
    Flavor   : AnsiChar;
    Retry    : Integer;
    NextTry  : LongWord;
  end;

  { Full mailer session — runs one inbound or outbound mail exchange }
  TMailSession = class
  private
    FIO        : TDXSockIO;
    FConfig    : TMailerConfig;
    FRemote    : TRemoteInfo;
    FIncoming  : Boolean;
    FNodelist  : TNodelistManager;
    FOnLog     : TMailerLog;
    FRecvFiles : TStringList;
    FSentFiles : TStringList;

    procedure Log(Level: TLogLevel; const Msg: string);
    function  DoNegotiate: Boolean;
    function  DoTransferReceive: Boolean;
    function  DoTransferSend: Boolean;
    function  DoBarkFreqs: Boolean;
    function  GetOutboundFiles(const Dest: TFidoAddr;
      List: TStringList): Integer;
    procedure TossReceived;
  public
    constructor Create(AIO: TDXSockIO; const ACfg: TMailerConfig;
      AIncoming: Boolean; ANodelist: TNodelistManager);
    destructor  Destroy; override;
    function    Run: Boolean;
    property    Remote: TRemoteInfo read FRemote;
    property    OnLog: TMailerLog read FOnLog write FOnLog;
  end;

  { Outbound poller }
  TMailerPoller = class
  private
    FConfig    : TMailerConfig;
    FQueue     : array of TPollEntry;
    FQueueLen  : Integer;
    FNodelist  : TNodelistManager;
    FOnLog     : TMailerLog;
    FRunning   : Boolean;

    procedure Log(Level: TLogLevel; const Msg: string);
    function  PollNode(const Entry: TPollEntry): Boolean;
    procedure LoadQueue;
    procedure SaveQueue;
  public
    constructor Create(const ACfg: TMailerConfig;
      ANodelist: TNodelistManager);
    destructor  Destroy; override;
    procedure   AddPoll(const Addr: TFidoAddr;
      const Phone, Password: string; Flavor: AnsiChar);
    procedure   RunOnce;
    procedure   Start;
    procedure   Stop;
    property    OnLog: TMailerLog read FOnLog write FOnLog;
  end;

  { Inbound listener — wraps TBPDXGenericServer }
  TMailerServer = class(TBPDXGenericServer)
  private
    FConfig    : TMailerConfig;
    FNodelist  : TNodelistManager;
    FOnLog     : TMailerLog;
    procedure Log(Level: TLogLevel; const Msg: string);
  protected
    procedure OnAcceptConnection(Sender: TObject;
      Socket: TBPDXSock); override;
    procedure OnProcessSession(Sender: TObject;
      Socket: TBPDXSock); override;
  public
    constructor Create(const ACfg: TMailerConfig;
      ANodelist: TNodelistManager);
    property OnLog: TMailerLog read FOnLog write FOnLog;
  end;

implementation

{ ====================== TMailSession ====================== }

constructor TMailSession.Create(AIO: TDXSockIO;
  const ACfg: TMailerConfig; AIncoming: Boolean;
  ANodelist: TNodelistManager);
begin
  inherited Create;
  FIO        := AIO;
  FConfig    := ACfg;
  FIncoming  := AIncoming;
  FNodelist  := ANodelist;
  FRecvFiles := TStringList.Create;
  FSentFiles := TStringList.Create;
end;

destructor TMailSession.Destroy;
begin
  FRecvFiles.Free;
  FSentFiles.Free;
  inherited;
end;

procedure TMailSession.Log(Level: TLogLevel; const Msg: string);
begin
  if Assigned(FOnLog) then FOnLog(Level, Msg);
end;

function TMailSession.DoNegotiate: Boolean;
var
  Sess: TObject;
begin
  if FIncoming then
  begin
    var AnsS := TAnswerSession.Create(FIO, FConfig);
    try
      Result := AnsS.Negotiate;
      if Result then
      begin
        FRemote := AnsS.Remote;
        Log(llInfo, 'Session: ' + SessionTypeNames[Ord(AnsS.SessionType)] +
          ' from ' + FidoAddrToStr(FRemote.Addrs[0]));
      end;
    finally
      AnsS.Free;
    end;
  end else
  begin
    { outbound: FRemote.Addrs[0] already set from poll entry }
    var NodeE: TNodelistEntry;
    FNodelist.Lookup(FRemote.Addrs[0], NodeE);
    var OrgS := TOriginateSession.Create(FIO, FConfig, NodeE);
    try
      Result := OrgS.Negotiate;
      if Result then
        FRemote := OrgS.Remote;
    finally
      OrgS.Free;
    end;
  end;
end;

function TMailSession.GetOutboundFiles(const Dest: TFidoAddr;
  List: TStringList): Integer;
var
  BM: TBundleManager;
begin
  BM := TBundleManager.Create(FConfig);
  try
    BM.GetOutboundFiles(Dest, List);
    Result := List.Count;
  finally
    BM.Free;
  end;
end;

function TMailSession.DoTransferReceive: Boolean;
{ Receive files from remote using ZModem }
var
  ZRcv: TZModemReceiver;
begin
  Result := False;
  if not FIO.DataAvail(3000) then
  begin
    Result := True;  { nothing to receive }
    Exit;
  end;
  ZRcv := TZModemReceiver.Create(FIO,
    FConfig.InboundDir);
  try
    var Res := ZRcv.ReceiveFiles(FRecvFiles);
    if Res in [zmOK, zmTimeout] then
    begin
      Log(llInfo, Format('Received %d file(s)', [FRecvFiles.Count]));
      Result := True;
    end else
      Log(llWarn, 'ZModem receive error: ' + IntToStr(Ord(Res)));
  finally
    ZRcv.Free;
  end;
end;

function TMailSession.DoTransferSend: Boolean;
{ Send outbound files to remote using ZModem }
var
  ToSend: TStringList;
  ZSend: TZModemSender;
  I: Integer;
  Res: TZModemResult;
begin
  Result := True;
  ToSend := TStringList.Create;
  try
    if FRemote.AddrCount = 0 then Exit;
    GetOutboundFiles(FRemote.Addrs[0], ToSend);
    if ToSend.Count = 0 then Exit;
    Log(llInfo, Format('Sending %d file(s)', [ToSend.Count]));
    ZSend := TZModemSender.Create(FIO);
    try
      for I := 0 to ToSend.Count-1 do
      begin
        Res := ZSend.SendFile(ToSend[I]);
        if Res = zmOK then
        begin
          FSentFiles.Add(ToSend[I]);
          DeleteFile(ToSend[I]);
          Log(llInfo, 'Sent: ' + ExtractFilename(ToSend[I]));
        end else
        begin
          Log(llWarn, 'ZModem send failed (' + ToSend[I] + '): ' +
            IntToStr(Ord(Res)));
          Result := False;
        end;
      end;
    finally
      ZSend.Free;
    end;
  finally
    ToSend.Free;
  end;
end;

function TMailSession.DoBarkFreqs: Boolean;
{ Answer FREQ requests from remote }
var
  BRcv: TBarkReceiver;
begin
  Result := True;
  BRcv := TBarkReceiver.Create(FIO, FConfig);
  try
    BRcv.AddFreqDir(FConfig.InboundDir);
    BRcv.AddFreqDir(FConfig.NetMailDir);
    Result := BRcv.AnswerRequests(FSentFiles);
  finally
    BRcv.Free;
  end;
end;

procedure TMailSession.TossReceived;
var
  Tosser: TTosser;
  I: Integer;
begin
  if FRecvFiles.Count = 0 then Exit;
  Tosser := TTosser.Create(FConfig);
  try
    for I := 0 to FRecvFiles.Count-1 do
    begin
      var Ext := UpperCase(ExtractFileExt(FRecvFiles[I]));
      if Ext = '.PKT' then
      begin
        var Log_ := Tosser.TossFile(FRecvFiles[I]);
        Log(llInfo, Format('Tossed %s: %d msgs, %d dupes, %d errors',
          [ExtractFilename(FRecvFiles[I]),
           Log_.MsgCount, Log_.Dupes, Log_.Errors]));
      end;
    end;
  finally
    Tosser.Free;
  end;
end;

function TMailSession.Run: Boolean;
begin
  Result := False;
  Log(llInfo, 'Session starting (' +
    IfThen(FIncoming, 'inbound', 'outbound') + ')');
  { 1. Negotiate session / handshake }
  if not DoNegotiate then
  begin
    Log(llWarn, 'Handshake failed');
    Exit;
  end;
  { 2. Receive inbound files }
  DoTransferReceive;
  { 3. Answer file requests (BARK FREQ) }
  DoBarkFreqs;
  { 4. Send outbound files }
  DoTransferSend;
  { 5. Toss received packets }
  TossReceived;
  Result := True;
  Log(llInfo, 'Session complete');
end;

const
  SessionTypeNames: array[TSessionType] of string =
    ('Unknown','FTS-0001','YooHoo','EMSI','BARK');

function IfThen(B: Boolean; const T, F: string): string;
begin
  if B then Result := T else Result := F;
end;

{ ====================== TMailerPoller ====================== }

constructor TMailerPoller.Create(const ACfg: TMailerConfig;
  ANodelist: TNodelistManager);
begin
  inherited Create;
  FConfig   := ACfg;
  FNodelist := ANodelist;
  FQueueLen := 0;
  FRunning  := False;
end;

destructor TMailerPoller.Destroy;
begin
  inherited;
end;

procedure TMailerPoller.Log(Level: TLogLevel; const Msg: string);
begin
  if Assigned(FOnLog) then FOnLog(Level, Msg);
end;

procedure TMailerPoller.AddPoll(const Addr: TFidoAddr;
  const Phone, Password: string; Flavor: AnsiChar);
begin
  if FQueueLen >= Length(FQueue) then
    SetLength(FQueue, Max(8, Length(FQueue)*2));
  FQueue[FQueueLen].Addr     := Addr;
  FQueue[FQueueLen].Phone    := Phone;
  FQueue[FQueueLen].Password := Password;
  FQueue[FQueueLen].Flavor   := Flavor;
  FQueue[FQueueLen].Retry    := 0;
  FQueue[FQueueLen].NextTry  := 0;
  Inc(FQueueLen);
end;

function TMailerPoller.PollNode(const Entry: TPollEntry): Boolean;
var
  Conn: TOutboundConn;
  Sess: TMailSession;
  NodeE: TNodelistEntry;
  Host: string;
  Port: Word;
begin
  Result := False;
  Host := Entry.Phone;
  Port := 24554;  { default FidoNet/IP port (IANA assigned) }
  { Try to get address from nodelist if phone is empty }
  if Host = '' then
  begin
    if FNodelist.Lookup(Entry.Addr, NodeE) then
    begin
      Host := NodeE.Phone;
      { Check if it's an IP address (INA:host:port flag) }
      var INA := '';
      var Flags := TStringList.Create;
      try
        Flags.Delimiter := ',';
        Flags.DelimitedText := NodeE.Flags;
        var I: Integer;
        for I := 0 to Flags.Count-1 do
          if Copy(UpperCase(Flags[I]),1,4) = 'INA:' then
          begin
            INA := Copy(Flags[I],5,999);
            Break;
          end else if Copy(UpperCase(Flags[I]),1,4) = 'IBN:' then
          begin
            INA := Copy(Flags[I],5,999);
            Port := 24554;
            Break;
          end;
      finally
        Flags.Free;
      end;
      if INA <> '' then
      begin
        { INA:host:port or just INA:host }
        var CP := Pos(':', INA);
        if CP > 0 then
        begin
          Port := StrToIntDef(Copy(INA,CP+1,999), 24554);
          Host := Copy(INA,1,CP-1);
        end else
          Host := INA;
      end;
    end;
  end;
  if Host = '' then
  begin
    Log(llWarn, 'No address for ' + FidoAddrToStr(Entry.Addr));
    Exit;
  end;
  Log(llInfo, 'Polling ' + FidoAddrToStr(Entry.Addr) +
    ' at ' + Host + ':' + IntToStr(Port));
  Conn := TOutboundConn.Create(FConfig);
  try
    if not Conn.Connect(Host, Port) then
    begin
      Log(llWarn, 'Connect failed to ' + Host);
      Exit;
    end;
    { Pre-set remote address for negotiate }
    var Sess_ := TMailSession.Create(Conn.IO, FConfig,
      False, FNodelist);
    try
      Sess_.Remote.Addrs[0] := Entry.Addr;
      Sess_.Remote.AddrCount := 1;
      Sess_.OnLog := FOnLog;
      Result := Sess_.Run;
    finally
      Sess_.Free;
    end;
  finally
    Conn.Free;
  end;
end;

procedure TMailerPoller.RunOnce;
var
  I: Integer;
  Now_: LongWord;
begin
  Now_ := LongWord(GetTickCount64 div 1000);
  for I := 0 to FQueueLen-1 do
  begin
    if FQueue[I].NextTry > Now_ then Continue;
    if PollNode(FQueue[I]) then
    begin
      { success — remove from queue or mark done }
      FQueue[I].Retry := 0;
    end else
    begin
      Inc(FQueue[I].Retry);
      FQueue[I].NextTry := Now_ + LongWord(300 * FQueue[I].Retry);
    end;
  end;
end;

procedure TMailerPoller.Start;
begin
  FRunning := True;
  repeat
    RunOnce;
    DoSleepEx(60000);  { poll every minute }
  until not FRunning;
end;

procedure TMailerPoller.Stop;
begin
  FRunning := False;
end;

{ ====================== TMailerServer ====================== }

constructor TMailerServer.Create(const ACfg: TMailerConfig;
  ANodelist: TNodelistManager);
begin
  inherited Create(nil);
  FConfig   := ACfg;
  FNodelist := ANodelist;
  Port      := ACfg.ListenPort;
  MaxConnections := ACfg.MaxSessions;
end;

procedure TMailerServer.Log(Level: TLogLevel; const Msg: string);
begin
  if Assigned(FOnLog) then FOnLog(Level, Msg);
end;

procedure TMailerServer.OnAcceptConnection(Sender: TObject;
  Socket: TBPDXSock);
begin
  { Accept all — filtering happens during handshake }
  Log(llInfo, 'Incoming connection from ' +
    Socket.PeerIPAddress + ':' + IntToStr(Socket.PeerPort));
end;

procedure TMailerServer.OnProcessSession(Sender: TObject;
  Socket: TBPDXSock);
var
  IO: TDXSockIO;
  Sess: TMailSession;
begin
  { This runs in a worker thread per DXSock generic server design }
  IO := TDXSockIO.Create(Socket, False);
  try
    Sess := TMailSession.Create(IO, FConfig, True, FNodelist);
    try
      Sess.OnLog := FOnLog;
      Sess.Run;
    finally
      Sess.Free;
    end;
  finally
    IO.Free;
    Socket.CloseGracefully;
  end;
end;

end.
