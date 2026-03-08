{ ==========================================================================
  FidoBark.pas — Bark file request protocol (FTS-0008)
  Handles both sending and receiving FREQ (file request) transactions
  ========================================================================== }
unit FidoBark;

{$MODE DELPHI}

interface

uses
  SysUtils, Classes, FidoNet, FidoZModem;

const
  BARK_FREQ_MAGIC = $C2;   { file request initiator byte }
  BARK_ACK        = $06;
  BARK_NAK        = $15;
  BARK_EOT        = $04;

type
  TBarkRequest = record
    Filename : string;
    Password : string;
    UpdateTime: LongWord;  { 0 = any }
  end;

  TBarkResult = (brOK, brDenied, brNotFound, brTimeout, brError);

  { Bark sender: sends file requests to remote }
  TBarkSender = class
  private
    FIO     : TByteIO;
    FConfig : TMailerConfig;
    function  BuildRequestBlock(const Req: TBarkRequest): AnsiString;
    function  WaitACK(TimeoutMs: Integer): Boolean;
  public
    constructor Create(AIO: TByteIO; const ACfg: TMailerConfig);
    function    SendRequest(const Req: TBarkRequest): TBarkResult;
    function    SendRequests(const Reqs: array of TBarkRequest): TBarkResult;
  end;

  { Bark receiver: answers file requests from remote }
  TBarkReceiver = class
  private
    FIO       : TByteIO;
    FConfig   : TMailerConfig;
    FFreqDirs : TStringList;
    FMaxFiles : Integer;
    FMaxBytes : Int64;

    function  FindFile(const Pattern: string;
      const Password: string; var FullPath: string): Boolean;
    function  ReadRequestBlock(var Req: TBarkRequest;
      TimeoutMs: Integer): Boolean;
  public
    constructor Create(AIO: TByteIO; const ACfg: TMailerConfig);
    destructor  Destroy; override;
    procedure   AddFreqDir(const Dir: string);
    function    AnswerRequests(SentFiles: TStringList): Boolean;
    property    MaxFiles : Integer read FMaxFiles write FMaxFiles;
    property    MaxBytes : Int64   read FMaxBytes write FMaxBytes;
  end;

implementation

{ ---------- TBarkSender ---------- }

constructor TBarkSender.Create(AIO: TByteIO;
  const ACfg: TMailerConfig);
begin
  inherited Create;
  FIO     := AIO;
  FConfig := ACfg;
end;

function TBarkSender.BuildRequestBlock(
  const Req: TBarkRequest): AnsiString;
{ Bark FREQ block: magic + filename + NUL + [password] + NUL + CR }
begin
  Result := Chr(BARK_FREQ_MAGIC) +
    Req.Filename;
  if Req.Password <> '' then
    Result := Result + '!' + Req.Password;
  if Req.UpdateTime <> 0 then
    Result := Result + '+' + IntToStr(Req.UpdateTime);
  Result := Result + #0 + #13;
end;

function TBarkSender.WaitACK(TimeoutMs: Integer): Boolean;
var
  B: Byte;
begin
  Result := FIO.RecvByte(B, TimeoutMs) and (B = BARK_ACK);
end;

function TBarkSender.SendRequest(const Req: TBarkRequest): TBarkResult;
var
  Blk: AnsiString;
  B: Byte;
begin
  Blk := BuildRequestBlock(Req);
  FIO.SendBuf(Blk[1], Length(Blk));
  { wait for ACK or NAK }
  if not FIO.RecvByte(B, 10000) then
  begin
    Result := brTimeout; Exit;
  end;
  case B of
    BARK_ACK : Result := brOK;
    BARK_NAK : Result := brDenied;
    BARK_EOT : Result := brNotFound;
  else
    Result := brError;
  end;
end;

function TBarkSender.SendRequests(
  const Reqs: array of TBarkRequest): TBarkResult;
var
  I: Integer;
  R: TBarkResult;
  B: Byte;
begin
  Result := brOK;
  for I := Low(Reqs) to High(Reqs) do
  begin
    R := SendRequest(Reqs[I]);
    if R <> brOK then
    begin
      Result := R; Exit;
    end;
  end;
  { send EOT to end FREQ session }
  B := BARK_EOT;
  FIO.SendBuf(B, 1);
end;

{ ---------- TBarkReceiver ---------- }

constructor TBarkReceiver.Create(AIO: TByteIO;
  const ACfg: TMailerConfig);
begin
  inherited Create;
  FIO       := AIO;
  FConfig   := ACfg;
  FFreqDirs := TStringList.Create;
  FMaxFiles := 10;
  FMaxBytes := 10 * 1024 * 1024;  { 10 MB default }
end;

destructor TBarkReceiver.Destroy;
begin
  FFreqDirs.Free;
  inherited;
end;

procedure TBarkReceiver.AddFreqDir(const Dir: string);
begin
  FFreqDirs.Add(IncludeTrailingPathDelimiter(Dir));
end;

function TBarkReceiver.FindFile(const Pattern: string;
  const Password: string; var FullPath: string): Boolean;
{ Find a file matching Pattern (may contain wildcards) in FREQ dirs }
var
  I: Integer;
  SR: TSearchRec;
  Dir: string;
begin
  Result := False;
  for I := 0 to FFreqDirs.Count-1 do
  begin
    Dir := FFreqDirs[I];
    if FindFirst(Dir + Pattern, faAnyFile and not faDirectory, SR) = 0 then
    begin
      FullPath := Dir + SR.Name;
      FindClose(SR);
      Result := True;
      Exit;
    end;
    FindClose(SR);
  end;
end;

function TBarkReceiver.ReadRequestBlock(var Req: TBarkRequest;
  TimeoutMs: Integer): Boolean;
{ Read: magic + filename [!password][+time] NUL CR }
var
  B: Byte;
  S: AnsiString;
  P: Integer;
begin
  Result := False;
  FillChar(Req, SizeOf(Req), 0);
  { first byte must be BARK_FREQ_MAGIC }
  if not FIO.RecvByte(B, TimeoutMs) then Exit;
  if B = BARK_EOT then
  begin
    { end of requests }
    Result := False;
    Req.Filename := #0;  { signal EOT }
    Exit;
  end;
  if B <> BARK_FREQ_MAGIC then Exit;
  { read until NUL }
  S := '';
  repeat
    if not FIO.RecvByte(B, 5000) then Exit;
    if B <> 0 then S := S + Chr(B);
  until (B = 0) or (Length(S) > 256);
  { skip trailing CR if present }
  FIO.RecvByte(B, 500);
  { parse: filename[!password][+time] }
  P := Pos('!', S);
  if P > 0 then
  begin
    Req.Filename := Copy(S,1,P-1);
    Req.Password := Copy(S,P+1,999);
    P := Pos('+', Req.Password);
    if P > 0 then
    begin
      Req.UpdateTime := StrToIntDef(Copy(Req.Password,P+1,999),0);
      Req.Password   := Copy(Req.Password,1,P-1);
    end;
  end else
  begin
    P := Pos('+', S);
    if P > 0 then
    begin
      Req.Filename   := Copy(S,1,P-1);
      Req.UpdateTime := StrToIntDef(Copy(S,P+1,999),0);
    end else
      Req.Filename := S;
  end;
  Result := (Req.Filename <> '');
end;

function TBarkReceiver.AnswerRequests(SentFiles: TStringList): Boolean;
{ Called after session handshake completes.
  Reads FREQ blocks, sends files via ZModem, returns True if clean EOT. }
var
  Req: TBarkRequest;
  FilePath: string;
  FilesSent: Integer;
  BytesSent: Int64;
  B: Byte;
  ZSend: TZModemSender;

  function DoWaitForFreqMagic: Boolean;
  begin
    { Bark starts when remote sends $C2 }
    Result := FIO.RecvByte(B, 5000) and (B = BARK_FREQ_MAGIC);
    { put it back by storing in Req.Filename trick:
      we don't have pushback, but we know it IS magic }
  end;

begin
  Result := False;
  FilesSent := 0;
  BytesSent := 0;
  { Wait up to 5 seconds for first FREQ magic }
  if not FIO.DataAvail(5000) then
  begin
    Result := True;  { no FREQ requested — normal }
    Exit;
  end;
  repeat
    if not ReadRequestBlock(Req, 10000) then Break;
    if Req.Filename = #0 then Break;   { EOT }
    if FindFile(Req.Filename, Req.Password, FilePath) and
       (FilesSent < FMaxFiles) and
       (BytesSent < FMaxBytes) then
    begin
      { Send ACK }
      B := BARK_ACK;
      FIO.SendBuf(B, 1);
      { Send file using ZModem }
      ZSend := TZModemSender.Create(FIO);
      try
        if ZSend.SendFile(FilePath) = zmOK then
        begin
          SentFiles.Add(FilePath);
          Inc(FilesSent);
          Inc(BytesSent, TFileStream.Create(FilePath,
            fmOpenRead).Size);
        end;
      finally
        ZSend.Free;
      end;
    end else
    begin
      { NAK — file not found or limit reached }
      B := BARK_NAK;
      FIO.SendBuf(B, 1);
    end;
  until False;
  Result := True;
end;

end.
