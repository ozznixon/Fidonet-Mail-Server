{ ==========================================================================
  FidoZModem.pas — ZModem / ZedZap file transfer protocol
  Implements ZRQINIT, ZRINIT, ZSINIT, ZFILE, ZDATA, ZEOF, ZFIN
  Compatible with ZedZap (overlapped I/O variant)
  ========================================================================== }
unit FidoZModem;

{$MODE DELPHI}

interface

uses
  SysUtils, Classes, FidoNet;

{ Abstract byte-I/O interface so the same code works over DXSock or serial }
type
  TByteIO = class
  public
    function  SendBuf(const Buf; Len: Integer): Boolean; virtual; abstract;
    function  RecvBuf(var Buf; Len: Integer;
                TimeoutMs: Integer): Integer; virtual; abstract;
    function  SendByte(B: Byte): Boolean; virtual;
    function  RecvByte(var B: Byte; TimeoutMs: Integer): Boolean; virtual;
    procedure Flush; virtual;
    procedure PurgeRx; virtual;
  end;

  TZModemResult = (zmOK, zmSKIP, zmAbort, zmTimeout, zmCRCError,
                   zmProtoError, zmFileError);

  TZModemProgressEvent = procedure(Sender: TObject; Filename: string;
    BytesDone, BytesTotal: Int64) of object;

  TZModemSender = class
  private
    FIO           : TByteIO;
    FTxBuf        : array[0..4095] of Byte;
    FLastRxPos    : LongWord;
    FZRInitFlags  : LongWord;
    FOnProgress   : TZModemProgressEvent;

    procedure SendZDLE(B: Byte);
    procedure SendHex(FrameType: Byte; const Data: array of Byte);
    procedure SendBinary32(FrameType: Byte; const Data: array of Byte);
    function  RecvHdr(var FrameType: Byte;
      var Data: array of Byte; TimeoutMs: Integer): Boolean;
    function  WaitForZRINIT(TimeoutMs: Integer): Boolean;
    function  SendZRQINIT: Boolean;
    function  SendZFILE(const Filename: string;
      FileSize: Int64): Boolean;
    function  SendZDATA(Stream: TStream; FileSize: Int64): TZModemResult;
    function  SendZFIN: Boolean;
    function  CRC32Block(const Buf; Len: Integer): LongWord;
  public
    constructor Create(AIO: TByteIO);
    function  SendFile(const Filename: string): TZModemResult;
    property  OnProgress: TZModemProgressEvent
      read FOnProgress write FOnProgress;
  end;

  TZModemReceiver = class
  private
    FIO           : TByteIO;
    FCanFDX       : Boolean;
    FOnProgress   : TZModemProgressEvent;
    FRecvDir      : string;

    procedure SendZRINIT;
    procedure SendZRPOS(Pos: LongWord);
    procedure SendZACK(Pos: LongWord);
    procedure SendZFIN;
    procedure SendHex(FrameType: Byte; const Data: array of Byte);
    function  RecvHdr(var FrameType: Byte;
      var Data: array of Byte; TimeoutMs: Integer): Boolean;
    function  RecvZFILE(var Filename: string;
      var FileSize: Int64; var StartPos: LongWord): Boolean;
    function  RecvZDATA(Stream: TStream;
      var Pos: LongWord): TZModemResult;
    function  CRC32Block(const Buf; Len: Integer): LongWord;
    function  CRC16Block(const Buf; Len: Integer): Word;
  public
    constructor Create(AIO: TByteIO; const ARecvDir: string);
    function  ReceiveFiles(ReceivedList: TStringList): TZModemResult;
    property  OnProgress: TZModemProgressEvent
      read FOnProgress write FOnProgress;
  end;

implementation

{ ---------- CRC tables (shared) ---------- }

function CalcCRC32(const Buf; Len: Integer): LongWord;
const
  T: array[0..255] of LongWord = (
    $00000000,$77073096,$EE0E612C,$990951BA,$076DC419,$706AF48F,$E963A535,$9E6495A3,
    $0EDB8832,$79DCB8A4,$E0D5E91B,$97D2D988,$09B64C2B,$7EB17CBF,$E7B82D09,$90BF1D3A,
    $1DB71064,$6AB020F2,$F3B97148,$84BE41DE,$1ADAD47D,$6DDDE4EB,$F4D4B551,$83D385C7,
    $136C9856,$646BA8C0,$FD62F97A,$8A65C9EC,$14015C4F,$63066CD9,$FA0F3D63,$8D080DF5,
    $3B6E20C8,$4C69105E,$D56041E4,$A2677172,$3C03E4D1,$4B04D447,$D20D85FD,$A50AB56B,
    $35B5A8FA,$42B2986C,$DBBBC9D6,$ACBCB9C0,$32D86CE3,$45DF5C75,$DCD60DCF,$ABD13D59,
    $26D930AC,$51DE003A,$C8D75180,$BFD06116,$21B4F4B5,$56B3C423,$CFBA9599,$B8BDA50F,
    $2802B89E,$5F058808,$C60CD9B2,$B10BE924,$2F6F7C87,$58684C11,$C1611DAB,$B6662D3D,
    $76DC4190,$01DB7106,$98D220BC,$EFD5102A,$71B18589,$06B6B51F,$9FBFE4A5,$E8B8D433,
    $7807C9A2,$0F00F934,$9609A88E,$E10E9818,$7F6A0DBB,$086D3D2D,$91646C97,$E6635C01,
    $6B6B51F4,$1C6C6162,$856530D8,$F262004E,$6C0695ED,$1B01A57B,$8208F4C1,$F50FC457,
    $65B0D9C6,$12B7E950,$8BBEB8EA,$FCB9887C,$62DD1D7F,$15DA2D49,$8CD37CF3,$FBD44C65,
    $4DB26158,$3AB551CE,$A3BC0074,$D4BB30E2,$4ADFA541,$3DD895D7,$A4D1C46D,$D3D6F4FB,
    $4369E96A,$346ED9FC,$AD678846,$DA60B8D0,$44042D73,$33031DE5,$AA0A4C5F,$DD0D7CC9,
    $5005713C,$270241AA,$BE0B1010,$C90C2086,$5768B525,$206F85B3,$B966D409,$CE61E49F,
    $5EDEF90E,$29D9C998,$B0D09822,$C7D7A8B4,$59B33D17,$2EB40D81,$B7BD5C3B,$C0BA6CAD,
    $EDB88320,$9ABFB3B6,$03B6E20C,$74B1D29A,$EAD54739,$9DD277AF,$04DB2615,$73DC1683,
    $E3630B12,$94643B84,$0D6D6A3E,$7A6A5AA8,$E40ECF0B,$9309FF9D,$0A00AE27,$7D079EB1,
    $F00F9344,$8708A3D2,$1E01F268,$6906C2FE,$F762575D,$806567CB,$196C3671,$6E6B06E7,
    $FED41B76,$89D32BE0,$10DA7A5A,$67DD4ACC,$F9B9DF6F,$8EBEEFF9,$17B7BE43,$60B08ED5,
    $D6D6A3E8,$A1D1937E,$38D8C2C4,$4FDFF252,$D1BB67F1,$A6BC5767,$3FB506DD,$48B2364B,
    $D80D2BDA,$AF0A1B4C,$36034AF6,$41047A60,$DF60EFC3,$A8670955,$316658C5,$4861AD53,
    $D66D3E3A,$A16D6FAC,$38646C14,$4F677882,$D82D7D96,$AF2A3700,$36235400,$41246450,
    $61B33D17,$16B40281,$8FBD51CB,$F8BA615D,$066DF4FE,$119B75FC,$88924440,$FF953476,
    $C096C530,$B5BFC6A6,$2CB6B51C,$5BB1858A,$9BD0A769,$ECB797FF,$75BEE645,$02B9D6D3,
    $A464F8CB,$D363C85D,$4A6AB9E7,$3D6D8971,$E30EAA22,$940DDAB4,$0D04AB0E,$7A039B98,
    $EB0E363F,$9C0906A9,$0500774B,$7207479D,$E40C343C,$932C04AA,$0A250540,$7D2235D6,
    $6A1936CE,$1D1E0658,$840D77E2,$F30A4774,$670F39E7,$100D0971,$890470CB,$FE034055,
    $B74B6B9D,$C04C5B0B,$594D2AB1,$2E4A1A27,$BA2F0CB4,$CD281C22,$542C6D98,$23293E2E,
    $A5566836,$D2515897,$4B5829C2,$3C5F1954,$A83A2DC7,$DF3D1D51,$465C6CEB,$314B5C7D,
    $4E197F08,$394E4F9E,$A04F3E24,$D7480EB2,$43257821,$343248B7,$AD33390D,$DA34099B,
    $CD3D0D83,$BA3A3D15,$234B4CAF,$546A5C39,$C00F68AA,$B7085803,$2E097943,$5B0E49D5,
    $0D56E8FD,$7A51D86B,$E350A9D1,$947F9947,$005CACE4,$774B9C72,$EE4AEDC8,$9A4DDD5E);
var
  I: Integer;
  CRC: LongWord;
  P: PByte;
begin
  CRC := $FFFFFFFF;
  P   := PByte(@Buf);
  for I := 0 to Len-1 do
  begin
    CRC := (CRC shr 8) xor T[(CRC xor P^) and $FF];
    Inc(P);
  end;
  Result := CRC xor $FFFFFFFF;
end;

function CalcCRC16(const Buf; Len: Integer): Word;
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
var
  I: Integer;
  CRC: Word;
  P: PByte;
begin
  CRC := 0;
  P   := PByte(@Buf);
  for I := 0 to Len-1 do
  begin
    CRC := (CRC shl 8) xor T[(CRC shr 8) xor P^];
    Inc(P);
  end;
  Result := CRC;
end;

{ ---------- TByteIO ---------- }

function TByteIO.SendByte(B: Byte): Boolean;
begin
  Result := SendBuf(B, 1);
end;

function TByteIO.RecvByte(var B: Byte; TimeoutMs: Integer): Boolean;
begin
  Result := RecvBuf(B, 1, TimeoutMs) = 1;
end;

procedure TByteIO.Flush;
begin
end;

procedure TByteIO.PurgeRx;
begin
end;

{ ---------- helpers ---------- }

const
  ZDLE_ESC_SET = [$11,$91,$13,$93,$18,$8D,$8F];

{ ---------- TZModemSender ---------- }

constructor TZModemSender.Create(AIO: TByteIO);
begin
  inherited Create;
  FIO := AIO;
end;

function TZModemSender.CRC32Block(const Buf; Len: Integer): LongWord;
begin
  Result := CalcCRC32(Buf, Len);
end;

procedure TZModemSender.SendZDLE(B: Byte);
var
  Pair: array[0..1] of Byte;
begin
  Pair[0] := ZDLE;
  Pair[1] := B xor $40;
  FIO.SendBuf(Pair, 2);
end;

procedure TZModemSender.SendHex(FrameType: Byte;
  const Data: array of Byte);
{ Send a ZHEX frame: **\030B<type><4 data bytes><CRC16>\r\n }
var
  S: AnsiString;
  CRC: Word;
  I: Integer;
  BufForCRC: array[0..4] of Byte;
begin
  BufForCRC[0] := FrameType;
  for I := 0 to 3 do BufForCRC[I+1] := Data[I];
  CRC := CalcCRC16(BufForCRC, 5);
  S := '**' + Chr(ZDLE) + Chr(ZHEX) +
    HexByte(FrameType);
  for I := 0 to 3 do S := S + HexByte(Data[I]);
  S := S + HexByte(Hi(CRC)) + HexByte(Lo(CRC));
  S := S + #13 + #10 + #17;  { CR LF XON }
  FIO.SendBuf(S[1], Length(S));
end;

procedure TZModemSender.SendBinary32(FrameType: Byte;
  const Data: array of Byte);
{ ZBIN32 frame }
var
  Header: array[0..4] of Byte;
  I: Integer;
  CRC: LongWord;
  B: Byte;

  procedure PutEscaped(X: Byte);
  begin
    if (X = ZDLE) or (X in ZDLE_ESC_SET) then
      SendZDLE(X)
    else
    begin
      B := X;
      FIO.SendBuf(B, 1);
    end;
  end;

begin
  { Preamble }
  B := ZPAD; FIO.SendBuf(B,1);
  B := ZDLE; FIO.SendBuf(B,1);
  B := ZBIN32; FIO.SendBuf(B,1);
  Header[0] := FrameType;
  for I := 0 to 3 do Header[I+1] := Data[I];
  for I := 0 to 4 do PutEscaped(Header[I]);
  CRC := CalcCRC32(Header, 5);
  PutEscaped(Lo(CRC));
  PutEscaped((CRC shr 8) and $FF);
  PutEscaped((CRC shr 16) and $FF);
  PutEscaped((CRC shr 24) and $FF);
end;

function TZModemSender.RecvHdr(var FrameType: Byte;
  var Data: array of Byte; TimeoutMs: Integer): Boolean;
var
  B, B2: Byte;
  Buf: array[0..7] of Byte;
  I, Got: Integer;

  function GetB(var X: Byte): Boolean;
  begin
    Result := FIO.RecvByte(X, TimeoutMs);
  end;

begin
  Result := False;
  FrameType := 255;
  { wait for ZPAD ZPAD ZDLE }
  repeat
    if not GetB(B) then Exit;
  until B = ZPAD;
  if not GetB(B) then Exit;
  if B = ZPAD then
    if not GetB(B) then Exit;
  if B <> ZDLE then Exit;
  if not GetB(B) then Exit;
  if B = ZHEX then
  begin
    { read 14 hex chars: type(2) data(8) crc(4) }
    for I := 0 to 6 do
    begin
      if not GetB(Buf[I*2]) then Exit;
      if not GetB(Buf[I*2+1]) then Exit;
    end;
    FrameType := (HexNibble(Buf[0]) shl 4) or HexNibble(Buf[1]);
    for I := 0 to 3 do
      Data[I] := (HexNibble(Buf[2+I*2]) shl 4) or
                  HexNibble(Buf[3+I*2]);
    { skip CR LF }
    GetB(B); GetB(B);
    Result := True;
  end
  else if (B = ZBIN) or (B = ZBIN32) then
  begin
    { read 5 bytes + CRC (escaped) }
    if not GetB(FrameType) then Exit;
    if FrameType = ZDLE then
    begin
      if not GetB(FrameType) then Exit;
      FrameType := FrameType xor $40;
    end;
    for I := 0 to 3 do
    begin
      if not GetB(Data[I]) then Exit;
      if Data[I] = ZDLE then
      begin
        if not GetB(Data[I]) then Exit;
        Data[I] := Data[I] xor $40;
      end;
    end;
    { skip CRC bytes }
    for I := 0 to 3 do GetB(B2);
    Result := True;
  end;
end;

function HexNibble(C: Byte): Byte;
begin
  if (C >= Ord('0')) and (C <= Ord('9')) then Result := C - Ord('0')
  else if (C >= Ord('A')) and (C <= Ord('F')) then Result := C - Ord('A') + 10
  else if (C >= Ord('a')) and (C <= Ord('f')) then Result := C - Ord('a') + 10
  else Result := 0;
end;

function TZModemSender.SendZRQINIT: Boolean;
var
  D: array[0..3] of Byte;
begin
  FillChar(D, 4, 0);
  SendHex(ZRQINIT, D);
  Result := True;
end;

function TZModemSender.WaitForZRINIT(TimeoutMs: Integer): Boolean;
var
  FT: Byte;
  D: array[0..3] of Byte;
  T0: LongWord;
begin
  Result := False;
  T0 := GetTickCount64;
  repeat
    if RecvHdr(FT, D, 2000) then
    begin
      if FT = ZRINIT then
      begin
        FZRInitFlags := D[0] or (LongWord(D[1]) shl 8);
        Result := True;
        Exit;
      end;
      if FT = ZCAN then Exit;
    end;
  until (GetTickCount64 - T0) > LongWord(TimeoutMs);
end;

function TZModemSender.SendZFILE(const Filename: string;
  FileSize: Int64): Boolean;
var
  D: array[0..3] of Byte;
  Info: AnsiString;
  FT: Byte;
  Resp: array[0..3] of Byte;
  B: Byte;
begin
  Result := False;
  FillChar(D, 4, 0);
  D[0] := $04;  { ZMNEW | ZCRESUM }
  { send ZFILE header }
  SendBinary32(ZFILE, D);
  { send file info block: "name size\0" }
  Info := ExtractFileName(Filename) + ' ' +
    IntToStr(FileSize) + #0;
  { send as data subpacket with ZCRCW }
  { simplified: send raw then CRC }
  B := ZDLE; FIO.SendBuf(B, 1);
  B := $6B {ZCRCW}; FIO.SendBuf(B, 1);
  FIO.SendBuf(Info[1], Length(Info));
  { wait for ZRPOS or ZSKIP or ZACK }
  if RecvHdr(FT, Resp, 10000) then
  begin
    if FT = ZRPOS then
    begin
      FLastRxPos := Resp[0] or (LongWord(Resp[1]) shl 8)
        or (LongWord(Resp[2]) shl 16) or (LongWord(Resp[3]) shl 24);
      Result := True;
    end
    else if FT = ZSKIP then
      Result := False;
  end;
end;

function TZModemSender.SendZDATA(Stream: TStream;
  FileSize: Int64): TZModemResult;
const
  BLKSIZE = 1024;
var
  Buf: array[0..BLKSIZE-1] of Byte;
  Rd, I: Integer;
  CRC: LongWord;
  B: Byte;
  FT: Byte;
  Resp: array[0..3] of Byte;
  Pos: LongWord;
  IsLast: Boolean;

  procedure SendEscaped(X: Byte);
  begin
    if (X = ZDLE) or (X in ZDLE_ESC_SET) then
    begin
      B := ZDLE; FIO.SendBuf(B,1);
      B := X xor $40; FIO.SendBuf(B,1);
    end else
    begin
      B := X; FIO.SendBuf(B,1);
    end;
  end;

begin
  Result := zmOK;
  Stream.Seek(FLastRxPos, soBeginning);
  Pos := FLastRxPos;
  { send ZDATA header with file position }
  var D: array[0..3] of Byte;
  D[0] := Pos and $FF;
  D[1] := (Pos shr 8) and $FF;
  D[2] := (Pos shr 16) and $FF;
  D[3] := (Pos shr 24) and $FF;
  SendBinary32(ZDATA, D);

  repeat
    Rd := Stream.Read(Buf, BLKSIZE);
    Inc(Pos, Rd);
    IsLast := (Pos >= LongWord(FileSize));
    { send data bytes escaped }
    for I := 0 to Rd-1 do
      SendEscaped(Buf[I]);
    { ZCRCE (end of file) or ZCRCG (more data) or ZCRCQ (request ACK) }
    B := ZDLE; FIO.SendBuf(B,1);
    if IsLast then B := $69 {ZCRCE}
    else B := $6A {ZCRCG};
    FIO.SendBuf(B, 1);
    CRC := CalcCRC32(Buf, Rd);
    SendEscaped(CRC and $FF);
    SendEscaped((CRC shr 8) and $FF);
    SendEscaped((CRC shr 16) and $FF);
    SendEscaped((CRC shr 24) and $FF);
    if IsLast then
    begin
      { wait for ZRINIT for next file or ZFIN }
      if RecvHdr(FT, Resp, 15000) then
      begin
        if FT = ZRINIT then Result := zmOK
        else if FT = ZFIN then Result := zmOK
        else if FT = ZRPOS then
        begin
          { resend from position — retry }
          Result := zmCRCError;
        end
        else Result := zmAbort;
      end else
        Result := zmTimeout;
    end;
    if Assigned(FOnProgress) then
      FOnProgress(Self, '', Pos, FileSize);
  until IsLast or (Result <> zmOK);
end;

function TZModemSender.SendZFIN: Boolean;
var
  D: array[0..3] of Byte;
  FT: Byte;
  Resp: array[0..3] of Byte;
  B: Byte;
begin
  FillChar(D, 4, 0);
  SendHex(ZFIN, D);
  Result := RecvHdr(FT, Resp, 5000) and (FT = ZFIN);
  if Result then
  begin
    B := Ord('O'); FIO.SendBuf(B,1);
    B := Ord('O'); FIO.SendBuf(B,1);
  end;
end;

function TZModemSender.SendFile(const Filename: string): TZModemResult;
var
  FS: TFileStream;
begin
  Result := zmFileError;
  if not FileExists(Filename) then Exit;
  FS := TFileStream.Create(Filename, fmOpenRead or fmShareDenyWrite);
  try
    SendZRQINIT;
    if not WaitForZRINIT(30000) then
    begin
      Result := zmTimeout; Exit;
    end;
    if not SendZFILE(Filename, FS.Size) then
    begin
      Result := zmSkip; Exit;
    end;
    Result := SendZDATA(FS, FS.Size);
    if Result = zmOK then
      SendZFIN;
  finally
    FS.Free;
  end;
end;

{ ---------- TZModemReceiver ---------- }

constructor TZModemReceiver.Create(AIO: TByteIO; const ARecvDir: string);
begin
  inherited Create;
  FIO      := AIO;
  FRecvDir := IncludeTrailingPathDelimiter(ARecvDir);
  FCanFDX  := True;
end;

function TZModemReceiver.CRC32Block(const Buf; Len: Integer): LongWord;
begin
  Result := CalcCRC32(Buf, Len);
end;

function TZModemReceiver.CRC16Block(const Buf; Len: Integer): Word;
begin
  Result := CalcCRC16(Buf, Len);
end;

procedure TZModemReceiver.SendHex(FrameType: Byte;
  const Data: array of Byte);
var
  S: AnsiString;
  CRC: Word;
  I: Integer;
  BufForCRC: array[0..4] of Byte;
begin
  BufForCRC[0] := FrameType;
  for I := 0 to 3 do BufForCRC[I+1] := Data[I];
  CRC := CalcCRC16(BufForCRC, 5);
  S := '**' + Chr(ZDLE) + Chr(ZHEX) + HexByte(FrameType);
  for I := 0 to 3 do S := S + HexByte(Data[I]);
  S := S + HexByte(Hi(CRC)) + HexByte(Lo(CRC));
  S := S + #13 + #10 + #17;
  FIO.SendBuf(S[1], Length(S));
end;

procedure TZModemReceiver.SendZRINIT;
var
  D: array[0..3] of Byte;
begin
  FillChar(D, 4, 0);
  D[0] := CANFDX or CANOVIO or CANFC32;
  SendHex(ZRINIT, D);
end;

procedure TZModemReceiver.SendZRPOS(Pos: LongWord);
var
  D: array[0..3] of Byte;
begin
  D[0] := Pos and $FF;
  D[1] := (Pos shr 8) and $FF;
  D[2] := (Pos shr 16) and $FF;
  D[3] := (Pos shr 24) and $FF;
  SendHex(ZRPOS, D);
end;

procedure TZModemReceiver.SendZACK(Pos: LongWord);
var
  D: array[0..3] of Byte;
begin
  D[0] := Pos and $FF;
  D[1] := (Pos shr 8) and $FF;
  D[2] := (Pos shr 16) and $FF;
  D[3] := (Pos shr 24) and $FF;
  SendHex(ZACK, D);
end;

procedure TZModemReceiver.SendZFIN;
var
  D: array[0..3] of Byte;
begin
  FillChar(D, 4, 0);
  SendHex(ZFIN, D);
end;

function TZModemReceiver.RecvHdr(var FrameType: Byte;
  var Data: array of Byte; TimeoutMs: Integer): Boolean;
{ Identical logic to sender side }
var
  B: Byte;
  Buf: array[0..13] of Byte;
  I: Integer;

  function GetB(var X: Byte): Boolean;
  begin
    Result := FIO.RecvByte(X, TimeoutMs);
  end;

begin
  Result := False;
  repeat
    if not GetB(B) then Exit;
  until B = ZPAD;
  if not GetB(B) then Exit;
  if B = ZPAD then
    if not GetB(B) then Exit;
  if B <> ZDLE then Exit;
  if not GetB(B) then Exit;
  if B = ZHEX then
  begin
    for I := 0 to 13 do
      if not GetB(Buf[I]) then Exit;
    FrameType := (HexNibble(Buf[0]) shl 4) or HexNibble(Buf[1]);
    for I := 0 to 3 do
      Data[I] := (HexNibble(Buf[2+I*2]) shl 4) or HexNibble(Buf[3+I*2]);
    GetB(B); GetB(B);
    Result := True;
  end else
  if (B = ZBIN) or (B = ZBIN32) then
  begin
    if not GetB(FrameType) then Exit;
    if FrameType = ZDLE then
    begin
      if not GetB(FrameType) then Exit;
      FrameType := FrameType xor $40;
    end;
    for I := 0 to 3 do
    begin
      if not GetB(Data[I]) then Exit;
      if Data[I] = ZDLE then
      begin
        if not GetB(Data[I]) then Exit;
        Data[I] := Data[I] xor $40;
      end;
    end;
    { skip CRC bytes (4) }
    for I := 0 to 3 do GetB(B);
    Result := True;
  end;
end;

function TZModemReceiver.RecvZFILE(var Filename: string;
  var FileSize: Int64; var StartPos: LongWord): Boolean;
{ Read the ZFILE data subpacket: "name size\0" }
var
  Info: AnsiString;
  B: Byte;
  P: Integer;
begin
  Result := False;
  Info := '';
  { read until null or timeout }
  while FIO.RecvByte(B, 5000) do
  begin
    if B = 0 then Break;
    if B = ZDLE then
    begin
      if not FIO.RecvByte(B, 5000) then Exit;
      B := B xor $40;
    end;
    Info := Info + Chr(B);
  end;
  P := Pos(' ', Info);
  if P = 0 then Exit;
  Filename := Copy(Info, 1, P-1);
  FileSize := StrToInt64Def(Copy(Info, P+1, 999), 0);
  StartPos := 0;
  Result := True;
end;

function TZModemReceiver.RecvZDATA(Stream: TStream;
  var Pos: LongWord): TZModemResult;
var
  B, B2: Byte;
  IsEOF: Boolean;
  CRC_Recv, CRC_Calc: LongWord;
  Chunk: array[0..4095] of Byte;
  ChunkLen: Integer;

  function GetEscaped(var X: Byte): Boolean;
  begin
    Result := FIO.RecvByte(X, 10000);
    if Result and (X = ZDLE) then
    begin
      Result := FIO.RecvByte(X, 10000);
      if Result then X := X xor $40;
    end;
  end;

begin
  Result := zmOK;
  IsEOF  := False;
  ChunkLen := 0;
  repeat
    if not GetEscaped(B) then
    begin
      Result := zmTimeout; Break;
    end;
    if B = ZDLE then
    begin
      { frame escape — read subpacket type }
      if not FIO.RecvByte(B2, 5000) then
      begin
        Result := zmTimeout; Break;
      end;
      if B2 = $69 {ZCRCE} then
        IsEOF := True
      else if B2 = $6A {ZCRCG} then
        IsEOF := False
      else if B2 = $6C {ZCRCQ} then
        IsEOF := False;  { ACK requested }
      { read 4 CRC bytes }
      var CRCBuf: array[0..3] of Byte;
      var I: Integer;
      for I := 0 to 3 do GetEscaped(CRCBuf[I]);
      CRC_Recv := CRCBuf[0] or (LongWord(CRCBuf[1]) shl 8)
        or (LongWord(CRCBuf[2]) shl 16) or (LongWord(CRCBuf[3]) shl 24);
      CRC_Calc := CalcCRC32(Chunk, ChunkLen);
      if CRC_Recv <> CRC_Calc then
      begin
        Result := zmCRCError;
        SendZRPOS(Pos);
        Break;
      end;
      Stream.WriteBuffer(Chunk, ChunkLen);
      Inc(Pos, ChunkLen);
      ChunkLen := 0;
      if Assigned(FOnProgress) then
        FOnProgress(Self, '', Pos, -1);
      if B2 = $6C then  { ZCRCQ — send ACK }
        SendZACK(Pos);
    end else
    begin
      if ChunkLen < SizeOf(Chunk) then
      begin
        Chunk[ChunkLen] := B;
        Inc(ChunkLen);
      end;
    end;
  until IsEOF or (Result <> zmOK);
end;

function TZModemReceiver.ReceiveFiles(ReceivedList: TStringList): TZModemResult;
var
  FT: Byte;
  D: array[0..3] of Byte;
  Filename: string;
  FullPath: string;
  FileSize: Int64;
  StartPos: LongWord;
  FS: TFileStream;
  FilesRecvd: Integer;
  B: Byte;
begin
  Result := zmOK;
  FilesRecvd := 0;
  SendZRINIT;
  repeat
    if not RecvHdr(FT, D, 30000) then
    begin
      Result := zmTimeout; Break;
    end;
    case FT of
      ZRQINIT:
        SendZRINIT;
      ZFILE:
      begin
        if not RecvZFILE(Filename, FileSize, StartPos) then
        begin
          Result := zmProtoError; Break;
        end;
        FullPath := FRecvDir + ExtractFileName(Filename);
        if FileExists(FullPath) then
          FS := TFileStream.Create(FullPath,
            fmOpenWrite or fmShareExclusive)
        else
          FS := TFileStream.Create(FullPath, fmCreate);
        try
          FS.Seek(StartPos, soBeginning);
          SendZRPOS(StartPos);
          Result := RecvZDATA(FS, StartPos);
          if Result = zmOK then
          begin
            ReceivedList.Add(FullPath);
            Inc(FilesRecvd);
            SendZRINIT;
          end;
        finally
          FS.Free;
        end;
      end;
      ZFIN:
      begin
        SendZFIN;
        { sender sends "OO" — read and discard }
        FIO.RecvByte(B, 2000);
        FIO.RecvByte(B, 2000);
        Break;
      end;
      ZCAN:
      begin
        Result := zmAbort; Break;
      end;
    end;
  until False;
end;

end.
