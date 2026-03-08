{ ==========================================================================
  FidoDXSock.pas — DXSock 6 adapter for FidoMailer
  Bridges TBPDXSock (DXSock6.pas) to TConnIO / TByteIO interfaces
  ========================================================================== }
unit FidoDXSock;

{$MODE DELPHI}

interface

uses
  SysUtils, Classes,
  DXSock6,                    { TBPDXSock, TBPDXNewConnect, TBPDXNewListen }
  dxutil_environment,         { DoSleepEx, TimeCounter }
  FidoNet,
  FidoSession,
  FidoZModem;

type
  { TConnIO implementation wrapping TBPDXSock }
  TDXSockIO = class(TConnIO)
  private
    FSock    : TBPDXSock;
    FOwned   : Boolean;
    FLineBuf : AnsiString;
    function  FillLineBuf(TimeoutMs: Integer): Boolean;
  public
    constructor Create(ASock: TBPDXSock; AOwned: Boolean = False);
    destructor  Destroy; override;

    { TByteIO overrides }
    function  SendBuf(const Buf; Len: Integer): Boolean; override;
    function  RecvBuf(var Buf; Len: Integer;
      TimeoutMs: Integer): Integer; override;
    procedure Flush; override;
    procedure PurgeRx; override;

    { TConnIO overrides }
    function  ReadLine(TimeoutMs: Integer): AnsiString; override;
    function  WriteLine(const S: AnsiString): Boolean; override;
    function  DataAvail(TimeoutMs: Integer): Boolean; override;
    function  Connected: Boolean; override;

    property  Sock: TBPDXSock read FSock;
  end;

  { Outbound (originating) mailer connection }
  TOutboundConn = class
  private
    FSock   : TBPDXSock;
    FIO     : TDXSockIO;
    FConfig : TMailerConfig;
  public
    constructor Create(const ACfg: TMailerConfig);
    destructor  Destroy; override;
    function    Connect(const Host: string; Port: Word): Boolean;
    procedure   Disconnect;
    property    IO: TDXSockIO read FIO;
    property    Connected: Boolean read FSock.Connected;
  end;

  { Inbound listener session — spawned per incoming connection }
  TInboundSession = class
  private
    FSock   : TBPDXSock;
    FIO     : TDXSockIO;
    FConfig : TMailerConfig;
  public
    constructor Create(ASock: TBPDXSock;
      const ACfg: TMailerConfig);
    destructor  Destroy; override;
    property    IO: TDXSockIO read FIO;
  end;

  { Generic server wrapping TBPDXGenericServer — listens on a port }
  TMailerListener = class
  private
    FServer  : TObject;       { TBPDXGenericServer — forward ref }
    FConfig  : TMailerConfig;
    FOnSession: procedure(Sock: TBPDXSock) of object;
  public
    constructor Create(const ACfg: TMailerConfig);
    destructor  Destroy; override;
    function    Start: Boolean;
    procedure   Stop;
    property    OnSession: procedure(Sock: TBPDXSock) of object
      read FOnSession write FOnSession;
  end;

implementation

uses
  dxsock_genericserver;   { TBPDXGenericServer }

{ ---------- TDXSockIO ---------- }

constructor TDXSockIO.Create(ASock: TBPDXSock; AOwned: Boolean);
begin
  inherited Create;
  FSock  := ASock;
  FOwned := AOwned;
end;

destructor TDXSockIO.Destroy;
begin
  if FOwned then FSock.Free;
  inherited;
end;

function TDXSockIO.SendBuf(const Buf; Len: Integer): Boolean;
begin
  Result := FSock.Write(Buf, Len) = Len;
end;

function TDXSockIO.RecvBuf(var Buf; Len: Integer;
  TimeoutMs: Integer): Integer;
{ DXSock doesn't have a single blocking recv with timeout; poll }
var
  T0: LongWord;
  Got: Integer;
  P: PByte;
begin
  Result := 0;
  P  := PByte(@Buf);
  T0 := GetTickCount64;
  while Result < Len do
  begin
    if FSock.Readable then
    begin
      Got := FSock.Read(P^, Len - Result);
      if Got > 0 then
      begin
        Inc(P, Got);
        Inc(Result, Got);
      end else if Got = 0 then
        Break;  { disconnected }
    end else
    begin
      if not FSock.Connected then Break;
      if (GetTickCount64 - T0) > LongWord(TimeoutMs) then Break;
      DoSleepEx(5);
    end;
  end;
end;

procedure TDXSockIO.Flush;
begin
  { DXSock flushes automatically; no-op }
end;

procedure TDXSockIO.PurgeRx;
var
  Dummy: array[0..511] of Byte;
begin
  FLineBuf := '';
  while FSock.Readable do
    FSock.Read(Dummy, SizeOf(Dummy));
end;

function TDXSockIO.FillLineBuf(TimeoutMs: Integer): Boolean;
{ Read data from socket into FLineBuf until we have a CR or LF }
var
  Chunk: array[0..255] of Byte;
  N, I: Integer;
  T0: LongWord;
begin
  Result := False;
  T0 := GetTickCount64;
  repeat
    if Pos(#10, FLineBuf) > 0 then
    begin
      Result := True; Exit;
    end;
    if FSock.Readable then
    begin
      N := FSock.Read(Chunk, SizeOf(Chunk));
      if N > 0 then
        for I := 0 to N-1 do
          FLineBuf := FLineBuf + Chr(Chunk[I]);
    end else
    begin
      if not FSock.Connected then Exit;
      DoSleepEx(5);
    end;
  until (GetTickCount64 - T0) > LongWord(TimeoutMs);
  Result := Pos(#10, FLineBuf) > 0;
end;

function TDXSockIO.ReadLine(TimeoutMs: Integer): AnsiString;
var
  P: Integer;
begin
  if FillLineBuf(TimeoutMs) then
  begin
    P := Pos(#10, FLineBuf);
    Result := Copy(FLineBuf, 1, P-1);
    FLineBuf := Copy(FLineBuf, P+1, MaxInt);
    { strip trailing CR }
    if (Length(Result) > 0) and (Result[Length(Result)] = #13) then
      SetLength(Result, Length(Result)-1);
  end else
    Result := '';
end;

function TDXSockIO.WriteLine(const S: AnsiString): Boolean;
var
  Line: AnsiString;
begin
  Line := S + #13 + #10;
  Result := SendBuf(Line[1], Length(Line));
end;

function TDXSockIO.DataAvail(TimeoutMs: Integer): Boolean;
var
  T0: LongWord;
begin
  if FLineBuf <> '' then
  begin
    Result := True; Exit;
  end;
  T0 := GetTickCount64;
  repeat
    if FSock.Readable then
    begin
      Result := True; Exit;
    end;
    if not FSock.Connected then
    begin
      Result := False; Exit;
    end;
    DoSleepEx(10);
  until (GetTickCount64 - T0) > LongWord(TimeoutMs);
  Result := False;
end;

function TDXSockIO.Connected: Boolean;
begin
  Result := FSock.Connected;
end;

{ ---------- TOutboundConn ---------- }

constructor TOutboundConn.Create(const ACfg: TMailerConfig);
begin
  inherited Create;
  FConfig := ACfg;
  FSock   := TBPDXSock.Create(nil);
  FIO     := TDXSockIO.Create(FSock, False);
end;

destructor TOutboundConn.Destroy;
begin
  FIO.Free;
  FSock.Free;
  inherited;
end;

function TOutboundConn.Connect(const Host: string; Port: Word): Boolean;
var
  Params: TBPDXNewConnect;
begin
  Params := TBPDXNewConnect.Create;
  try
    Params.Address := Host;
    Params.Port    := Port;
    Params.Timeout := FConfig.ConnectTimeout * 1000;
    FSock.Connect(Params);
    var T0 := GetTickCount64;
    while not FSock.Connected do
    begin
      if FSock.DroppedConnection then
      begin
        Result := False; Exit;
      end;
      if (GetTickCount64 - T0) >
         LongWord(FConfig.ConnectTimeout * 1000) then
      begin
        Result := False; Exit;
      end;
      DoSleepEx(50);
    end;
    Result := FSock.Connected;
  finally
    Params.Free;
  end;
end;

procedure TOutboundConn.Disconnect;
begin
  FSock.CloseGracefully;
end;

{ ---------- TInboundSession ---------- }

constructor TInboundSession.Create(ASock: TBPDXSock;
  const ACfg: TMailerConfig);
begin
  inherited Create;
  FSock   := ASock;
  FConfig := ACfg;
  FIO     := TDXSockIO.Create(FSock, False);
end;

destructor TInboundSession.Destroy;
begin
  FIO.Free;
  inherited;
end;

{ ---------- TMailerListener ---------- }

constructor TMailerListener.Create(const ACfg: TMailerConfig);
begin
  inherited Create;
  FConfig := ACfg;
  FServer := TBPDXGenericServer.Create(nil);
end;

destructor TMailerListener.Destroy;
begin
  TBPDXGenericServer(FServer).Free;
  inherited;
end;

function TMailerListener.Start: Boolean;
var
  Srv: TBPDXGenericServer;
begin
  Srv := TBPDXGenericServer(FServer);
  Srv.Port    := FConfig.ListenPort;
  Srv.MaxConnections := FConfig.MaxSessions;
  Srv.OnAcceptConnection := @InternalOnAccept;
  Srv.OnProcessSession   := @InternalOnSession;
  Srv.Start;
  Result := True;
end;

procedure TMailerListener.Stop;
begin
  TBPDXGenericServer(FServer).Stop;
end;

{ Internal callbacks — these are not usable directly as method pointers
  in the generic server because they differ in signature.
  In production, subclass TBPDXGenericServer and override OnProcessSession. }

end.
