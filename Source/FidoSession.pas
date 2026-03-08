{ ==========================================================================
  FidoSession.pas — EMSI / YooHoo / FTS-0001 session handshake protocols
  Supports: EMSI (FSP-1023), YooHoo/2U2 (FTS-0006), plain FTS-0001
  ========================================================================== }
unit FidoSession;

{$MODE DELPHI}

interface

uses
  SysUtils, Classes, FidoNet, FidoZModem;

type
  { Remote system information collected during handshake }
  TRemoteInfo = record
    Addrs       : array of TFidoAddr;
    AddrCount   : Integer;
    SysOpName   : string;
    SystemName  : string;
    Location    : string;
    Phone       : string;
    Password    : string;
    Flags       : string;     { EMSI capability flags }
    ProtoCaps   : string;     { e.g. "ZMO ZAP" }
    SessionType : TSessionType;
    MakerID     : string;
    MakerVer    : string;
  end;

  { Abstract connection I/O — implemented by DXSockIO in FidoMailer.pas }
  TConnIO = class(TByteIO)
  public
    function  ReadLine(TimeoutMs: Integer): AnsiString; virtual; abstract;
    function  WriteLine(const S: AnsiString): Boolean; virtual; abstract;
    function  DataAvail(TimeoutMs: Integer): Boolean; virtual; abstract;
    function  Connected: Boolean; virtual; abstract;
  end;

  { Answer (incoming call) session negotiator }
  TAnswerSession = class
  private
    FIO      : TConnIO;
    FConfig  : TMailerConfig;
    FRemote  : TRemoteInfo;
    FSessionType: TSessionType;

    { EMSI }
    function  BuildEMSIDat: AnsiString;
    function  ParseEMSIDat(const S: AnsiString): Boolean;
    function  CalcEMSICRC(const Data: AnsiString): Word;
    function  DoEMSIAnswer: Boolean;

    { YooHoo/2U2 }
    function  BuildYooHooBlock: AnsiString;
    function  ParseYooHooBlock(const Blk: AnsiString): Boolean;
    function  DoYooHooAnswer: Boolean;

    { FTS-0001 FTSC handshake }
    function  DoFTSCAnswer: Boolean;
  public
    constructor Create(AIO: TConnIO; const ACfg: TMailerConfig);
    function  Negotiate: Boolean;
    property  Remote: TRemoteInfo read FRemote;
    property  SessionType: TSessionType read FSessionType;
  end;

  { Originate (outgoing call) session negotiator }
  TOriginateSession = class
  private
    FIO      : TConnIO;
    FConfig  : TMailerConfig;
    FRemote  : TRemoteInfo;
    FTarget  : TNodeEntry;
    FSessionType: TSessionType;

    function  BuildEMSIDat: AnsiString;
    function  ParseEMSIDat(const S: AnsiString): Boolean;
    function  CalcEMSICRC(const Data: AnsiString): Word;
    function  DoEMSIOriginate: Boolean;
    function  DoYooHooOriginate: Boolean;
    function  DoFTSCOriginate: Boolean;
  public
    constructor Create(AIO: TConnIO; const ACfg: TMailerConfig;
      const ATarget: TNodeEntry);
    function  Negotiate: Boolean;
    property  Remote: TRemoteInfo read FRemote;
    property  SessionType: TSessionType read FSessionType;
  end;

implementation

{ ====================== CRC helpers ====================== }

function CalcCRC16ForEMSI(const S: AnsiString): Word;
{ CRC-16/CCITT on the string bytes }
var
  I: Integer;
  CRC: Word;
  B: Byte;
const
  T: array[0..255] of Word = (
    $0000,$1021,$2042,$3063,$4084,$50A5,$60C6,$70E7,
    $8108,$9129,$A14A,$B16B,$C18C,$D1AD,$E1CE,$F1EF,
    $1231,$0210,$3273,$2252,$52B5,$4294,$72F7,$62D6,
    $9339,$8318,$B37B,$A35A,$D3BD,$C39C,$F3FF,$E3DE,
    $2462,$3443,$0420,$1401,$64E6,$74C7,$44A4,$5485,
    $A56A,$B54B,$8528,$9509,$E5EE,$F5CF,$C5AC,$D58D,
    $3653,$2672,$1611,$0630,$76D7,$66F6,$5695,$46B4,
    $B75B,$A77A,$9719,$8738,$F7FF,$E7DE,$D7BD,$C79C,
    $4864,$5845,$6826,$7807,$08E0,$18C1,$28A2,$3883,
    $C96C,$D94D,$E92E,$F90F,$89E8,$99C9,$A9AA,$B98B,
    $5255,$4274,$7237,$6216,$12F1,$02D0,$32B3,$2292,
    $D27D,$C25C,$F23F,$E21E,$92F9,$82D8,$B2BB,$A29A,
    $6426,$7407,$4464,$5445,$24A2,$3483,$0CE0,$1CC1,
    $ED2E,$FD0F,$CD6C,$DD4D,$ADAA,$BD8B,$8DE8,$9DC9,
    $7653,$6672,$5611,$4630,$36D7,$26F6,$16B5,$06D4,
    $F73B,$E71A,$D779,$C758,$B7BF,$A79E,$97FD,$87DC,
    $E864,$F845,$C826,$D807,$A8E0,$B8C1,$88A2,$98C3,
    $6966,$7947,$4924,$5905,$29E2,$39C3,$09A0,$1981,
    $F96E,$E94F,$D92C,$C90D,$B9EA,$A9CB,$99A8,$89C9,
    $5116,$4137,$7154,$6175,$11B2,$01D3,$31B0,$2191,
    $C060,$D041,$E022,$F003,$80E4,$90C5,$A0A6,$B087,
    $5B68,$4B49,$7B2A,$6B0B,$1BEC,$0BCD,$3BAE,$2B8F,
    $CA40,$DA61,$EA02,$FA23,$8AE4,$9AC5,$AAA6,$BAD7,
    $5B88,$4BA9,$7BCA,$6BEB,$1B2C,$0B0D,$3B6E,$2B4F,
    $D4B1,$C490,$F4F3,$E4D2,$9435,$8414,$B477,$A456,
    $5CB9,$4C98,$7CFB,$6CDA,$1C3D,$0C1C,$3C7F,$2C5E,
    $E5E1,$F5C0,$C5A3,$D582,$A565,$B544,$8527,$9506,
    $65E9,$75C8,$45AB,$558A,$256D,$354C,$052F,$150E,
    $F6E1,$E6C0,$D6A3,$C682,$B665,$A644,$9627,$8606,
    $76C9,$66E8,$568B,$46AA,$36ED,$26CC,$16AF,$06EE,
    $E71F,$F73E,$C75D,$D77C,$A79B,$B7BA,$87D9,$97F8,
    $6817,$7836,$4855,$5874,$28B3,$38D2,$08B1,$18D0);
begin
  CRC := $FFFF;
  for I := 1 to Length(S) do
  begin
    B   := Ord(S[I]);
    CRC := (CRC shl 8) xor T[(CRC shr 8) xor B];
  end;
  Result := CRC;
end;

{ ====================== EMSI helpers ====================== }

function EMSIField(const S: string): string;
{ Escape special chars for EMSI data fields }
var
  I: Integer;
  R: string;
begin
  R := '';
  for I := 1 to Length(S) do
    case S[I] of
      '\','{','}' : R := R + '\' + S[I];
    else
      R := R + S[I];
    end;
  Result := R;
end;

function UnEMSIField(const S: string): string;
var
  I: Integer;
  R: string;
begin
  R := '';
  I := 1;
  while I <= Length(S) do
  begin
    if (S[I] = '\') and (I < Length(S)) then
    begin
      Inc(I);
      R := R + S[I];
    end else
      R := R + S[I];
    Inc(I);
  end;
  Result := R;
end;

function EMSIAddrList(const Cfg: TMailerConfig): string;
var
  I: Integer;
begin
  Result := FidoAddrToStr(Cfg.Address);
  for I := 0 to Cfg.AKACount-1 do
    Result := Result + ' ' + FidoAddrToStr(Cfg.AKAs[I]);
end;

{ ====================== TAnswerSession ====================== }

constructor TAnswerSession.Create(AIO: TConnIO;
  const ACfg: TMailerConfig);
begin
  inherited Create;
  FIO     := AIO;
  FConfig := ACfg;
  FillChar(FRemote, SizeOf(FRemote), 0);
  FSessionType := stUnknown;
end;

function TAnswerSession.CalcEMSICRC(const Data: AnsiString): Word;
begin
  Result := CalcCRC16ForEMSI(Data);
end;

function TAnswerSession.BuildEMSIDat: AnsiString;
{ Builds **EMSI_DAT<hex-len><data><CRC16> }
var
  AddrStr, Data, Inner: AnsiString;
  CRC: Word;
begin
  AddrStr := EMSIAddrList(FConfig);
  { EMSI_DAT format:
      {EMSI}{addrs}{name,sysop,location,phone,speed}{proto}{caps}{password}{time} }
  Inner :=
    '{EMSI}' +
    '{' + EMSIField(AddrStr) + '}' +
    '{' + EMSIField(FConfig.SystemName) + ',' +
          EMSIField(FConfig.SysOpName) + ',' +
          EMSIField(FConfig.Location) + ',' +
          EMSIField(FConfig.Phone) + ',300,33600}' +
    '{ZMO,ZAP,NCP}' +
    '{8N1,XON}' +
    '{' + EMSIField(FConfig.Password) + '}' +
    '{' + FormatDateTime('YYYYMMDD HHMMSS', Now) + '}';
  Data := Inner;
  CRC  := CalcEMSICRC(Data);
  Result := EMSI_DAT_HDR +
    HexWord(Length(Data)) +
    Data +
    HexWord(CRC);
end;

function TAnswerSession.ParseEMSIDat(const S: AnsiString): Boolean;
{ Parse **EMSI_DAT<hex-len><data><CRC16> }
var
  DataStart, DataLen: Integer;
  Data, Field: AnsiString;
  P, Q: Integer;
  Fields: TStringList;
  I: Integer;
  AddrList: TStringList;
begin
  Result := False;
  if Copy(S,1,10) <> EMSI_DAT_HDR then Exit;
  DataLen := StrToIntDef('$' + Copy(S, 11, 4), 0);
  DataStart := 15;
  if DataStart + DataLen > Length(S) then Exit;
  Data := Copy(S, DataStart, DataLen);
  { CRC check }
  { parse fields { ... } }
  Fields := TStringList.Create;
  AddrList := TStringList.Create;
  try
    P := 1;
    while P <= Length(Data) do
    begin
      if Data[P] = '{' then
      begin
        Q := P+1;
        while (Q <= Length(Data)) and (Data[Q] <> '}') do
          Inc(Q);
        Fields.Add(UnEMSIField(Copy(Data, P+1, Q-P-1)));
        P := Q+1;
      end else
        Inc(P);
    end;
    if Fields.Count < 3 then Exit;
    { field 0 = EMSI, field 1 = addresses, field 2 = sysinfo }
    AddrList.Delimiter := ' ';
    AddrList.DelimitedText := Fields[1];
    SetLength(FRemote.Addrs, AddrList.Count);
    FRemote.AddrCount := 0;
    for I := 0 to AddrList.Count-1 do
      if StrToFidoAddr(AddrList[I], FRemote.Addrs[FRemote.AddrCount]) then
        Inc(FRemote.AddrCount);
    { sysinfo: name,sysop,location,phone,... }
    if Fields.Count > 2 then
    begin
      var SysInfo := Fields[2];
      var Comma: Integer;
      Comma := Pos(',', SysInfo);
      if Comma > 0 then
      begin
        FRemote.SystemName := Copy(SysInfo,1,Comma-1);
        SysInfo := Copy(SysInfo,Comma+1,999);
        Comma := Pos(',', SysInfo);
        if Comma > 0 then
        begin
          FRemote.SysOpName := Copy(SysInfo,1,Comma-1);
          SysInfo := Copy(SysInfo,Comma+1,999);
          Comma := Pos(',', SysInfo);
          if Comma > 0 then
            FRemote.Location := Copy(SysInfo,1,Comma-1);
        end;
      end;
    end;
    if Fields.Count > 3 then FRemote.ProtoCaps := Fields[3];
    if Fields.Count > 5 then FRemote.Password  := Fields[5];
    Result := True;
  finally
    AddrList.Free;
    Fields.Free;
  end;
end;

function TAnswerSession.DoEMSIAnswer: Boolean;
{ EMSI answer sequence:
  Receiver: send EMSI_REQ repeatedly
  Caller:   sends EMSI_DAT
  Receiver: sends EMSI_DAT + EMSI_ACK
  Caller:   sends EMSI_ACK }
var
  Line: AnsiString;
  Retries: Integer;
  GotDat: Boolean;
  B: Byte;
begin
  Result := False;
  GotDat := False;
  { Send EMSI_REQ three times to prompt caller }
  for Retries := 1 to 3 do
  begin
    FIO.WriteLine(EMSI_REQ_HDR);
    if FIO.DataAvail(2000) then Break;
  end;
  { Wait for EMSI_DAT (up to 60s) }
  for Retries := 1 to 20 do
  begin
    Line := FIO.ReadLine(3000);
    if Copy(Line,1,10) = EMSI_DAT_HDR then
    begin
      if ParseEMSIDat(Line) then
      begin
        GotDat := True;
        Break;
      end;
    end;
    { EMSI heartbeat }
    if Copy(Line,1,10) = EMSI_HBT_HDR then Continue;
    if not FIO.Connected then Exit;
  end;
  if not GotDat then Exit;
  { Send our EMSI_DAT }
  FIO.WriteLine(BuildEMSIDat);
  { Send EMSI_ACK x2 }
  FIO.WriteLine(EMSI_ACK_HDR + '0000');
  FIO.WriteLine(EMSI_ACK_HDR + '0000');
  { Wait for caller's EMSI_ACK }
  for Retries := 1 to 5 do
  begin
    Line := FIO.ReadLine(5000);
    if Copy(Line,1,10) = EMSI_ACK_HDR then
    begin
      Result := True;
      FRemote.SessionType := stEMSI;
      FSessionType := stEMSI;
      Exit;
    end;
    if Copy(Line,1,10) = EMSI_HBT_HDR then Continue;
  end;
end;

function TAnswerSession.BuildYooHooBlock: AnsiString;
{ YooHoo block: 128-byte binary structure }
var
  Blk: array[0..127] of Byte;
  Addr: TFidoAddr;
  I: Integer;
  S: AnsiString;
begin
  FillChar(Blk, 128, 0);
  Blk[0]  := YOOHOO_MAGIC;
  Blk[1]  := 0;  { version }
  Addr := FConfig.Address;
  Blk[2]  := Lo(Addr.Net);  Blk[3]  := Hi(Addr.Net);
  Blk[4]  := Lo(Addr.Node); Blk[5]  := Hi(Addr.Node);
  Blk[6]  := Lo(Addr.Zone); Blk[7]  := Hi(Addr.Zone);
  { capabilities: ZMO=1, ZAP=2 }
  Blk[8]  := $03;
  Blk[9]  := 0;
  { SysOp name: 20 chars at offset 10 }
  S := Copy(FConfig.SysOpName, 1, 20);
  for I := 1 to Length(S) do Blk[9+I] := Ord(S[I]);
  { System name: 30 chars at offset 30 }
  S := Copy(FConfig.SystemName, 1, 30);
  for I := 1 to Length(S) do Blk[29+I] := Ord(S[I]);
  { CRC16 at bytes 126-127 }
  var CRC := CalcCRC16ForEMSI(Copy(AnsiString(
    RawByteString(PAnsiChar(@Blk))), 1, 126));
  Blk[126] := Lo(CRC);
  Blk[127] := Hi(CRC);
  SetLength(Result, 128);
  Move(Blk, Result[1], 128);
end;

function TAnswerSession.ParseYooHooBlock(const Blk: AnsiString): Boolean;
var
  I: Integer;
  S: AnsiString;
begin
  Result := False;
  if Length(Blk) < 128 then Exit;
  if Ord(Blk[1]) <> YOOHOO_MAGIC then Exit;
  SetLength(FRemote.Addrs, 1);
  FRemote.Addrs[0].Net  := Ord(Blk[3]) or (Ord(Blk[4]) shl 8);
  FRemote.Addrs[0].Node := Ord(Blk[5]) or (Ord(Blk[6]) shl 8);
  FRemote.Addrs[0].Zone := Ord(Blk[7]) or (Ord(Blk[8]) shl 8);
  FRemote.AddrCount := 1;
  S := '';
  for I := 11 to 30 do
    if Blk[I] <> #0 then S := S + Blk[I];
  FRemote.SysOpName := TrimStr(S);
  S := '';
  for I := 31 to 60 do
    if Blk[I] <> #0 then S := S + Blk[I];
  FRemote.SystemName := TrimStr(S);
  Result := True;
end;

function TAnswerSession.DoYooHooAnswer: Boolean;
{ YooHoo answer: wait for TSYNC, send our block, wait for theirs, ACK }
var
  B: Byte;
  Retries: Integer;
  BlkBuf: AnsiString;
  I, N, Got: Integer;

begin
   Result := False;
  { Wait for TSYNC ($AE) or YooHoo ($F4) }
   for Retries := 1 to 30 do begin
      if not FIO.RecvByte(B, 1000) then Continue;
      if (B = TSYNC) or (B = YOOHOO_MAGIC) then Break;
      if not FIO.Connected then Exit;
   end;
   if (B <> TSYNC) and (B <> YOOHOO_MAGIC) then Exit;
  { Send our YooHoo block }
   BlkBuf := BuildYooHooBlock;
   FIO.SendBuf(BlkBuf[1], 128);
  { Wait for their YooHoo block }
   SetLength(BlkBuf, 128);
   Got := 0;
   while Got < 128 do begin
      N := FIO.RecvBuf(BlkBuf[Got+1], 128-Got, 5000);
      if N <= 0 then Exit;
      Inc(Got, N);
   end;
   if not ParseYooHooBlock(BlkBuf) then Exit;
  { Send ACK }
   B := ACK;
   FIO.SendBuf(B, 1);
   FRemote.SessionType := stYooHoo;
   FSessionType        := stYooHoo;
   Result := True;
end;

function TAnswerSession.DoFTSCAnswer: Boolean;
{ Minimal FTS-0001 answer: wait for ENQ, send TSYNC banner, exchange nodelist }
var
  B: Byte;

begin
   Result := False;
   if not FIO.RecvByte(B, 5000) then Exit;
   if B <> ENQ then Exit;
  { Send banner: "FIDO\r" }
   FIO.WriteLine('ZCZC');
   FRemote.SessionType := stFTS1;
   FSessionType        := stFTS1;
   Result := True;
end;

function TAnswerSession.Negotiate: Boolean;
var
  B: Byte;
  Retries: Integer;
  Line: AnsiString;

begin
   Result := False;
  { Detect session type from first bytes }
   for Retries := 1 to 60 do begin
       if not FIO.DataAvail(1000) then Continue;
       if not FIO.RecvByte(B, 500) then Continue;
    { EMSI_REQ / EMSI_DAT detection: starts with '*' }
       if B = Ord('*') then begin
       Line := '*' + FIO.ReadLine(3000);
       if Copy(Line,1,10) = EMSI_REQ_HDR then begin
          Result := DoEMSIAnswer;
          Exit;
       end;
       if Copy(Line,1,10) = EMSI_DAT_HDR then begin
        { caller went straight to DAT }
          if ParseEMSIDat(Line) then begin
             FIO.WriteLine(BuildEMSIDat);
             FIO.WriteLine(EMSI_ACK_HDR + '0000');
             FIO.WriteLine(EMSI_ACK_HDR + '0000');
             FRemote.SessionType := stEMSI;
             FSessionType := stEMSI;
             Result := True;
          end;
          Exit;
       end;
    end
    else if B = YOOHOO_MAGIC then begin
       Result := DoYooHooAnswer;
       Exit;
    end
    else if B = TSYNC then begin
       Result := DoYooHooAnswer;
       Exit;
    end
    else if B = ENQ then begin
       Result := DoFTSCAnswer;
       Exit;
    end;
    if not FIO.Connected then Exit;
   end;
end;

{ ====================== TOriginateSession ====================== }

constructor TOriginateSession.Create(AIO: TConnIO;
  const ACfg: TMailerConfig; const ATarget: TNodeEntry);

begin
   inherited Create;
   FIO      := AIO;
   FConfig  := ACfg;
   FTarget  := ATarget;
   FillChar(FRemote, SizeOf(FRemote), 0);
   FSessionType := stUnknown;
end;

function TOriginateSession.CalcEMSICRC(const Data: AnsiString): Word;
begin
   Result := CalcCRC16ForEMSI(Data);
end;

function TOriginateSession.BuildEMSIDat: AnsiString;
var
  AddrStr, Data, Inner: AnsiString;
  CRC: Word;

begin
   AddrStr := EMSIAddrList(FConfig);
   Inner :='{EMSI}' +
       '{' + EMSIField(AddrStr) + '}' +
       '{' + EMSIField(FConfig.SystemName) + ',' +
       EMSIField(FConfig.SysOpName) + ',' +
       EMSIField(FConfig.Location) + ',' +
       EMSIField(FConfig.Phone) + ',300,33600}' +
       '{ZMO,ZAP,NCP}' +
       '{8N1,XON}' +
       '{' + EMSIField(FTarget.Password) + '}' +
       '{' + FormatDateTime('YYYYMMDD HHMMSS', Now) + '}';
   Data := Inner;
   CRC  := CalcEMSICRC(Data);
   Result := EMSI_DAT_HDR + HexWord(Length(Data)) + Data + HexWord(CRC);
end;

function TOriginateSession.ParseEMSIDat(const S: AnsiString): Boolean;
var
  DataStart, DataLen: Integer;
  Data, Field, SysInfo: AnsiString;
  P, Q: Integer;
  Fields: TStringList;
  AddrList: TStringList;
  I, Comma: Integer;

begin
   Result := False;
   if Copy(S,1,10) <> EMSI_DAT_HDR then Exit;
   DataLen   := StrToIntDef('$' + Copy(S,11,4), 0);
   DataStart := 15;
   if DataStart + DataLen > Length(S) then Exit;
   Data := Copy(S, DataStart, DataLen);
   Fields   := TStringList.Create;
   AddrList := TStringList.Create;
try
   P := 1;
   while P <= Length(Data) do begin
      if Data[P] = '{' then begin
         Q := P+1;
         while (Q <= Length(Data)) and (Data[Q] <> '}') do Inc(Q);
         Fields.Add(UnEMSIField(Copy(Data,P+1,Q-P-1)));
         P := Q+1;
      end
      else Inc(P);
   end;
   if Fields.Count < 2 then Exit;
   AddrList.Delimiter := ' ';
   AddrList.DelimitedText := Fields[1];
   SetLength(FRemote.Addrs, AddrList.Count);
   FRemote.AddrCount := 0;
   for I := 0 to AddrList.Count-1 do
      if StrToFidoAddr(AddrList[I], FRemote.Addrs[FRemote.AddrCount]) then
         Inc(FRemote.AddrCount);
   if Fields.Count > 2 then begin
      SysInfo := Fields[2];
      Comma := Pos(',', SysInfo);
      if Comma > 0 then begin
         FRemote.SystemName := Copy(SysInfo,1,Comma-1);
         SysInfo := Copy(SysInfo,Comma+1,999);
         Comma := Pos(',', SysInfo);
         if Comma > 0 then begin
            FRemote.SysOpName := Copy(SysInfo,1,Comma-1);
            SysInfo := Copy(SysInfo,Comma+1,999);
            Comma := Pos(',',SysInfo);
            if Comma > 0 then FRemote.Location := Copy(SysInfo,1,Comma-1);
         end;
      end;
   end;
   if Fields.Count > 3 then FRemote.ProtoCaps := Fields[3];
   if Fields.Count > 5 then FRemote.Password  := Fields[5];
   Result := True;
finally
   AddrList.Free;
   Fields.Free;
end;
end;

function TOriginateSession.DoEMSIOriginate: Boolean;
var
  Line: AnsiString;
  Retries: Integer;
  GotDat: Boolean;

begin
   Result  := False;
   GotDat  := False;
  { Send EMSI_REQ to announce EMSI capability }
   FIO.WriteLine(EMSI_REQ_HDR);
  { Send our EMSI_DAT }
   FIO.WriteLine(BuildEMSIDat);
  { Wait for remote's EMSI_DAT }
   for Retries := 1 to 20 do begin
      Line := FIO.ReadLine(3000);
      if Copy(Line,1,10) = EMSI_DAT_HDR then begin
         if ParseEMSIDat(Line) then begin
            GotDat := True;
            Break;
         end;
      end;
      if Copy(Line,1,10) = EMSI_HBT_HDR then Continue;
      if not FIO.Connected then Exit;
   end;
   if not GotDat then Exit;
  { Send ACK }
   FIO.WriteLine(EMSI_ACK_HDR + '0000');
   FIO.WriteLine(EMSI_ACK_HDR + '0000');
  { Wait for remote ACK }
   for Retries := 1 to 5 do begin
      Line := FIO.ReadLine(5000);
      if Copy(Line,1,10) = EMSI_ACK_HDR then begin
         Result := True;
         FRemote.SessionType := stEMSI;
         FSessionType := stEMSI;
         Exit;
      end;
      if Copy(Line,1,10) = EMSI_HBT_HDR then Continue;
   end;
end;

function TOriginateSession.DoYooHooOriginate: Boolean;
var
  B: Byte;
  Retries: Integer;
  BlkBuf: AnsiString;
  Got,N: Integer;

begin
   Result := False;
   { Send TSYNC to signal YooHoo intent }
   B := TSYNC;
   FIO.SendBuf(B, 1);
   B := YOOHOO_MAGIC;
   FIO.SendBuf(B, 1);
   { Wait for remote YooHoo block }
   SetLength(BlkBuf, 128);
   Got := 0;
   while Got < 128 do begin
      N := FIO.RecvBuf(BlkBuf[Got+1], 128-Got, 5000);
      if N <= 0 then Exit;
      Inc(Got, N);
   end;
   if not ParseYooHooBlock(BlkBuf) then Exit;
  { Send our block }
   BlkBuf := BuildYooHooBlock;
   FIO.SendBuf(BlkBuf[1], 128);
  { Wait for ACK }
   for Retries := 1 to 10 do begin
      if not FIO.RecvByte(B, 2000) then Continue;
      if B = ACK then begin
         FRemote.SessionType := stYooHoo;
         FSessionType        := stYooHoo;
         Result := True;
         Exit;
      end;
   end;
end;

function TOriginateSession.ParseYooHooBlock(const Blk: AnsiString): Boolean;
var
  I: Integer;
  S: AnsiString;

begin
  Result := False;
  if Length(Blk) < 128 then Exit;
  SetLength(FRemote.Addrs, 1);
  FRemote.Addrs[0].Net  := Ord(Blk[3]) or (Ord(Blk[4]) shl 8);
  FRemote.Addrs[0].Node := Ord(Blk[5]) or (Ord(Blk[6]) shl 8);
  FRemote.Addrs[0].Zone := Ord(Blk[7]) or (Ord(Blk[8]) shl 8);
  FRemote.AddrCount := 1;
  S := '';
  for I := 11 to 30 do
    if Blk[I] <> #0 then S := S + Blk[I];
  FRemote.SysOpName := TrimStr(S);
  S := '';
  for I := 31 to 60 do
    if Blk[I] <> #0 then S := S + Blk[I];
  FRemote.SystemName := TrimStr(S);
  Result := True;
end;

function TOriginateSession.BuildYooHooBlock: AnsiString;
var
  Blk: array[0..127] of Byte;
  S: AnsiString;
  I: Integer;

begin
  FillChar(Blk, 128, 0);
  Blk[0] := YOOHOO_MAGIC;
  Blk[2] := Lo(FConfig.Address.Net);  Blk[3] := Hi(FConfig.Address.Net);
  Blk[4] := Lo(FConfig.Address.Node); Blk[5] := Hi(FConfig.Address.Node);
  Blk[6] := Lo(FConfig.Address.Zone); Blk[7] := Hi(FConfig.Address.Zone);
  Blk[8] := $03;
  S := Copy(FConfig.SysOpName,1,20);
  for I := 1 to Length(S) do Blk[9+I] := Ord(S[I]);
  S := Copy(FConfig.SystemName,1,30);
  for I := 1 to Length(S) do Blk[29+I] := Ord(S[I]);
  var CRC := CalcCRC16ForEMSI(Copy(AnsiString(
    RawByteString(PAnsiChar(@Blk))),1,126));
  Blk[126] := Lo(CRC); Blk[127] := Hi(CRC);
  SetLength(Result,128);
  Move(Blk, Result[1], 128);
end;

function TOriginateSession.DoFTSCOriginate: Boolean;
var
  B: Byte;

begin
  Result := False;
  B := ENQ;
  FIO.SendBuf(B, 1);
  if not FIO.RecvByte(B, 5000) then Exit;
  FRemote.SessionType := stFTS1;
  FSessionType        := stFTS1;
  Result := True;
end;

function TOriginateSession.Negotiate: Boolean;
begin
  { Try EMSI first (most capable), fall back to YooHoo, then FTS-0001 }
  Result := DoEMSIOriginate;
  if not Result then
    Result := DoYooHooOriginate;
  if not Result then
    Result := DoFTSCOriginate;
end;

end.
