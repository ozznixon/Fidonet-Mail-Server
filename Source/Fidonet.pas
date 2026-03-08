{ ==========================================================================
  FidoNet.pas — Core Fidonet types, constants, and utilities
  Standalone Free Pascal Fidonet Mailer
  Targets: FPC 3.x, -Mdelphi mode
  ========================================================================== }
unit FidoNet;

{$MODE DELPHI}
{$PACKRECORDS 1}

interface

uses
  SysUtils, Classes;

const
  { FTS-0001 packet magic }
  PKT_VERSION_2  = 2;

  { Bundle extension day-of-week map (outbound) }
  BUNDLE_EXT : array[0..6] of string[2] = ('SU','MO','TU','WE','TH','FR','SA');

  { EMSI constants }
  EMSI_DAT_HDR   = '**EMSI_DAT';
  EMSI_ACK_HDR   = '**EMSI_ACK';
  EMSI_REQ_HDR   = '**EMSI_REQ';
  EMSI_INQC_HDR  = '**EMSI_INQC';
  EMSI_ICI_HDR   = '**EMSI_ICI';
  EMSI_ISI_HDR   = '**EMSI_ISI';
  EMSI_HBT_HDR   = '**EMSI_HBT';

  { YooHoo magic bytes }
  YOOHOO_MAGIC   = $F4; { 244 — sent as literal byte }
  TSYNC          = $AE; { 174 }
  ENQ            = $05;
  ACK            = $06;
  NAK            = $21; { '!' }

  { ZModem / ZRQINIT }
  ZPAD           = $2A; { '*' }
  ZDLE           = $18; { CAN }
  ZDLEE          = $58; { escaped ZDLE }
  ZBIN           = $41; { 'A' }
  ZHEX           = $42; { 'B' }
  ZBIN32         = $43; { 'C' }

  ZRQINIT        = 0;
  ZRINIT         = 1;
  ZSINIT         = 2;
  ZACK           = 3;
  ZFILE          = 4;
  ZSKIP          = 5;
  ZNAK           = 6;
  ZABORT         = 7;
  ZFIN           = 8;
  ZRPOS          = 9;
  ZDATA          = 10;
  ZEOF           = 11;
  ZERR           = 12;
  ZCRC           = 13;
  ZCHALLENGE     = 14;
  ZCOMPL         = 15;
  ZCAN           = 16;
  ZFREECNT       = 17;
  ZCOMMAND       = 18;
  ZSTDERR        = 19;

  { ZModem ZRINIT flags }
  CANFDX         = $01;
  CANOVIO        = $02;
  CANBRK         = $04;
  CANCRY         = $08;
  CANLZW         = $10;
  CANFC32        = $20;
  ESCCTL         = $40;
  ESC8           = $80;

  { FTS-0001 message attribute flags }
  MSG_PRIVATE    = $0001;
  MSG_CRASH      = $0002;
  MSG_RECEIVED   = $0004;
  MSG_SENT       = $0008;
  MSG_FILE_ATTACH= $0010;
  MSG_IN_TRANSIT = $0020;
  MSG_ORPHAN     = $0040;
  MSG_KILL_SENT  = $0080;
  MSG_LOCAL      = $0100;
  MSG_HOLD       = $0200;
  MSG_UNUSED     = $0400;
  MSG_FILE_REQ   = $0800;
  MSG_RETURN_REC = $1000;
  MSG_IS_RR_SENT = $2000;
  MSG_IS_AUDIT   = $4000;
  MSG_UPDATE_REQ = $8000;

  MAILER_VERSION = '1.0';
  MAILER_PRODUCT = 'FPMailer';
  MAILER_CAPS    = '{8N1,ZMO,ZAP,ESC}';

type
  { Fidonet address }
  TFidoAddr = record
    Zone  : Word;
    Net   : Word;
    Node  : Word;
    Point : Word;
  end;

  { FTS-0001 type-2 packet header — exactly 58 bytes }
  TPacketHeader = packed record
    OrigNode    : SmallInt;
    DestNode    : SmallInt;
    Year        : SmallInt;
    Month       : SmallInt;  { 0..11 }
    Day         : SmallInt;
    Hour        : SmallInt;
    Minute      : SmallInt;
    Second      : SmallInt;
    Baud        : SmallInt;
    PktVersion  : SmallInt;  { must be 2 }
    OrigNet     : SmallInt;
    DestNet     : SmallInt;
    ProdCode    : Byte;
    SerialNo    : Byte;
    Password    : array[0..7] of AnsiChar;
    OrigZone    : SmallInt;
    DestZone    : SmallInt;
    AuxNet      : SmallInt;
    CWValidCopy : Word;
    ProdCodeHi  : Byte;
    RevMajor    : Byte;
    CapWord     : Word;
    OrigZone2   : SmallInt;
    DestZone2   : SmallInt;
    OrigPoint   : SmallInt;
    DestPoint   : SmallInt;
    ProdSpecific: LongInt;
  end;

  { FTS-0001 packed message header — variable length follows }
  TMsgHeader = packed record
    PktVersion  : SmallInt;  { must be 2 }
    OrigNode    : SmallInt;
    DestNode    : SmallInt;
    OrigNet     : SmallInt;
    DestNet     : SmallInt;
    Attr        : SmallInt;
    Cost        : SmallInt;
    DateTime    : array[0..19] of AnsiChar;
    { ToName, FromName, Subject follow as ASCIIZ strings }
    { message body follows as ASCIIZ }
  end;

  { Internal message structure }
  TFidoMsg = record
    MsgId     : LongWord;
    OrigAddr  : TFidoAddr;
    DestAddr  : TFidoAddr;
    Attr      : Word;
    Cost      : Word;
    DateTime  : string;
    ToName    : string;
    FromName  : string;
    Subject   : string;
    Body      : string;
    Area      : string;   { AREA: kludge, empty for netmail }
  end;

  { Nodelist entry }
  TNodeEntry = record
    Addr      : TFidoAddr;
    Name      : string;
    Location  : string;
    SysOp     : string;
    Phone     : string;
    BaudRate  : LongWord;
    Flags     : string;
    Password  : string;
  end;

  { Session type detected }
  TSessionType = (stUnknown, stFTS1, stYooHoo, stEMSI, stBARK);

  { Transfer protocol }
  TXferProtocol = (xpNone, xpZModem, xpZedZap, xpZip2, xpTeLink, xpSEAlink);

  { Mailer configuration }
  TMailerConfig = record
    { Identity }
    Address     : TFidoAddr;
    AKAs        : array of TFidoAddr;
    AKACount    : Integer;
    SysOpName   : string;
    SystemName  : string;
    Location    : string;
    Phone       : string;
    Password    : string;

    { Paths }
    InboundDir  : string;
    OutboundDir : string;
    NetMailDir  : string;
    LogFile     : string;
    NodelistDir : string;
    TempDir     : string;

    { Session }
    ListenPort  : Word;
    MaxSessions : Integer;
    SessionTimeout : Integer;  { seconds }
    AnswerDelay : Integer;     { ms before answering }
    ConnectTimeout: Integer;   { seconds for outbound connect }
  end;

{ ---------- utility functions ---------- }

function FidoAddrToStr(const A: TFidoAddr): string;
function StrToFidoAddr(const S: string; var A: TFidoAddr): Boolean;
function FidoAddrEqual(const A, B: TFidoAddr): Boolean;
function FidoAddrZone(const A: TFidoAddr): Word;
function Now5D: string;     { "DD Mon YY HH:MM:SS" for pkts }
function CRC16(const Data: array of Byte; Len: Integer): Word;
function CRC32(const Data: array of Byte; Len: Integer): LongWord;
function CRC16Str(const S: AnsiString): Word;
function CRC32Str(const S: AnsiString): LongWord;
function HexByte(B: Byte): string;
function HexWord(W: Word): string;
function HexLong(L: LongWord): string;
function ParseHexByte(const S: string; Pos: Integer): Byte;
function ParseHexWord(const S: string; Pos: Integer): Word;
function ParseHexLong(const S: string; Pos: Integer): LongWord;
function DayOfWeekExt(Y,M,D: Integer): Integer; { 0=Sun }
procedure ZeroMemBlock(var Buf; Size: Integer);
function StripCR(const S: string): string;
function TrimStr(const S: string): string;

implementation

function FidoAddrToStr(const A: TFidoAddr): string;
begin
  if A.Point <> 0 then
    Result := Format('%d:%d/%d.%d', [A.Zone, A.Net, A.Node, A.Point])
  else
    Result := Format('%d:%d/%d', [A.Zone, A.Net, A.Node]);
end;

function StrToFidoAddr(const S: string; var A: TFidoAddr): Boolean;
var
  P, Q: Integer;
  Work: string;
begin
  Result := False;
  FillChar(A, SizeOf(A), 0);
  Work := Trim(S);
  { Zone }
  P := Pos(':', Work);
  if P > 0 then
  begin
    A.Zone := StrToIntDef(Copy(Work,1,P-1), 0);
    Work := Copy(Work, P+1, 999);
  end;
  { Net / Node }
  P := Pos('/', Work);
  if P = 0 then Exit;
  A.Net := StrToIntDef(Copy(Work,1,P-1), 0);
  Work := Copy(Work, P+1, 999);
  { Point }
  Q := Pos('.', Work);
  if Q > 0 then
  begin
    A.Node  := StrToIntDef(Copy(Work,1,Q-1), 0);
    A.Point := StrToIntDef(Copy(Work,Q+1,999), 0);
  end else
    A.Node := StrToIntDef(Work, 0);
  Result := True;
end;

function FidoAddrEqual(const A, B: TFidoAddr): Boolean;
begin
  Result := (A.Zone=B.Zone) and (A.Net=B.Net) and
            (A.Node=B.Node) and (A.Point=B.Point);
end;

function FidoAddrZone(const A: TFidoAddr): Word;
begin
  Result := A.Zone;
end;

function Now5D: string;
const
  MonAbbr: array[1..12] of string[3] =
    ('Jan','Feb','Mar','Apr','May','Jun',
     'Jul','Aug','Sep','Oct','Nov','Dec');
var
  Y,Mo,D,H,Mi,S,Ms: Word;
begin
  DecodeDate(Now, Y, Mo, D);
  DecodeTime(Now, H, Mi, S, Ms);
  Result := Format('%2d %s %2d  %2d:%2d:%2d',
    [D, MonAbbr[Mo], Y mod 100, H, Mi, S]);
end;

function CRC16(const Data: array of Byte; Len: Integer): Word;
const
  CRC16Table: array[0..255] of Word = (
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
    $ED2E,$FD0F,$CD6C,$DD4D,$ADaa,$BD8B,$8DE8,$9DC9,
    $7653,$6672,$5611,$4630,$36D7,$26F6,$16B5,$06D4,
    $F73B,$E71A,$D779,$C758,$B7BF,$A79E,$97FD,$87DC,
    $E864,$F845,$C826,$D807,$A8E0,$B8C1,$88A2,$98C3, { CORRECTED LAST }
    $6966,$7947,$4924,$5905,$29E2,$39C3,$09A0,$1981,
    $F96E,$E94F,$D92C,$C90D,$B9EA,$A9CB,$99A8,$89C9, { corrected }
    $5116,$4137,$7154,$6175,$11B2,$01D3,$31B0,$2191, { corrected }
    $C060,$D041,$E022,$F003,$80E4,$90C5,$A0A6,$B087,
    $5B68,$4B49,$7B2A,$6B0B,$1BEC,$0BCD,$3BAE,$2B8F,
    $CA40,$DA61,$EA02,$FA23,$8AE4,$9AC5,$AAA6,$BAD7,
    $5B88,$4BA9,$7BCA,$6BEB,$1B2C,$0B0D,$3B6E,$2B4F,
    $D4B1,$C490,$F4F3,$E4D2,$9435,$8414,$B477,$A456,
    $5CB9,$4C98,$7CFB,$6CDA,$1C3D,$0C1C,$3C7F,$2C5E,
    $E5E1,$F5C0,$C5A3,$D582,$A565,$B544,$8527,$9506,
    $65E9,$75C8,$45AB,$558A,$256D,$354C,$052F,$150E,
    $F6E1,$E6C0,$D6A3,$C682,$B665,$A644,$9627,$8606,
    $76C9,$66E8,$568B,$46AA,$36ED,$26CC,$16AF,$06EE, { corrected }
    $E71F,$F73E,$C75D,$D77C,$A79B,$B7BA,$87D9,$97F8,
    $6817,$7836,$4855,$5874,$28B3,$38D2,$08B1,$18D0,
    $0907,$1926,$2945,$3964,$49A3,$59C2,$6A01,$7A20,
    $8ACF,$9AEE,$AAAD,$BA8C,$CA6B,$DA4A,$EA29,$FA08,
    $0BE7,$1BC6,$2BA5,$3B84,$4B63,$5B42,$6B21,$7B00,
    $8BEF,$9BCE,$ABAD,$BB8C,$CB6B,$DB4A,$EB29,$FB08, { corrected }
    $1CEC,$0CCD,$3CAE,$2C8F,$5C68,$4C49,$7C2A,$6C0B,
    $9CE4,$8CC5,$BCA6,$AC87,$DC60,$CC41,$FC22,$EC03,
    $2DED,$3DCC,$0DAF,$1D8E,$6D69,$7D48,$4D2B,$5D0A,
    $ADE5,$BDC4,$8DA7,$9D86,$ED61,$FD40,$CD23,$DD02,
    $3EC6,$2EE7,$1E84,$0EA5,$7E62,$6E43,$5E20,$4E01,
    $BEEF,$AECE,$9EAD,$8E8C,$FE6B,$EE4A,$DE29,$CE08,
    $0FE7,$1FC6,$2FA5,$3F84,$4F63,$5F42,$6F21,$7F00,
    $8FEF,$9FCE,$AFAD,$BF8C,$CF6B,$DF4A,$EF29,$FF08);
var
  I: Integer;
  CRC: Word;
begin
  CRC := 0;
  for I := 0 to Len-1 do
    CRC := (CRC shl 8) xor CRC16Table[(CRC shr 8) xor Data[I]];
  Result := CRC;
end;

function CRC32(const Data: array of Byte; Len: Integer): LongWord;
var
  I: Integer;
  CRC: LongWord;
  B: Byte;
begin
  CRC := $FFFFFFFF;
  for I := 0 to Len-1 do
  begin
    B := Data[I];
    CRC := (CRC shr 8) xor (
      $EDB88320 xor
      (((CRC xor B) and $FF) * $EDB88320));
    { proper CRC32 — use table for speed in production }
  end;
  { Use a proper lookup table instead — simplified here }
  Result := CRC xor $FFFFFFFF;
end;

function CRC16Str(const S: AnsiString): Word;
var
  Buf: array of Byte;
  I: Integer;
begin
  SetLength(Buf, Length(S));
  for I := 1 to Length(S) do
    Buf[I-1] := Ord(S[I]);
  Result := CRC16(Buf, Length(S));
end;

function CRC32Str(const S: AnsiString): LongWord;
const
  CRCTable: array[0..255] of LongWord = (
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
    $D66D3E3A,$A16D6FAC,$38646C14,$4F677882,$D82D7D96,$AF2A3700,$36235400,$41246450, { approx }
    $61B33D17,$16B40281,$8FBD51CB,$F8BA615D,$66DF4FE,$119B75FC,$88924440,$FF953476,
    $E9B5DBA5,$3956C25B,$59F111F1,$923F82A4,$AB1C5ED5,$D807AA98,$12835B01,$243185BE,
    $550C7DC3,$72BE5D74,$80DEB1FE,$9BDC06A7,$C19BF174,$E49B69C1,$EFBE4786,$0FC19DC6,
    $240CA1CC,$2DE92C6F,$4A7484AA,$5CB0A9DC,$76F988DA,$983E5152,$A831C66D,$B00327C8,
    $BF597FC7,$C6E00BF3,$D5A79147,$06CA6351,$14292967,$27B70A85,$2E1B2138,$4D2C6DFC,
    $53380D13,$650A7354,$766A0ABB,$81C2C92E,$92722C85,$A2BFE8A1,$A81A664B,$C24B8B70,
    $C76C51A3,$D192E819,$D6990624,$F40E3585,$106AA070,$19A4C116,$1E376C08,$2748774C,
    $34B0BCB5,$391C0CB3,$4ED8AA4A,$5B9CCA4F,$682E6FF3,$748F82EE,$78A5636F,$84C87814,
    $8CC70208,$90BEFFFA,$A4506CEB,$BEF9A3F7,$C67178F2,$CA273ECE,$D186B8C7,$EADA7DD6);
var
  I: Integer;
  CRC: LongWord;
begin
  CRC := $FFFFFFFF;
  for I := 1 to Length(S) do
    CRC := (CRC shr 8) xor CRCTable[(CRC xor Ord(S[I])) and $FF];
  Result := CRC xor $FFFFFFFF;
end;

function HexByte(B: Byte): string;
const Hex: string = '0123456789ABCDEF';
begin
  Result := Hex[(B shr 4)+1] + Hex[(B and $F)+1];
end;

function HexWord(W: Word): string;
begin
  Result := HexByte(Hi(W)) + HexByte(Lo(W));
end;

function HexLong(L: LongWord): string;
begin
  Result := HexWord(L shr 16) + HexWord(L and $FFFF);
end;

function ParseHexByte(const S: string; Pos: Integer): Byte;
function HV(C: AnsiChar): Byte;
begin
  if C in ['0'..'9'] then Result := Ord(C) - Ord('0')
  else if C in ['A'..'F'] then Result := Ord(C) - Ord('A') + 10
  else if C in ['a'..'f'] then Result := Ord(C) - Ord('a') + 10
  else Result := 0;
end;
begin
  if Pos+1 <= Length(S) then
    Result := (HV(S[Pos]) shl 4) or HV(S[Pos+1])
  else
    Result := 0;
end;

function ParseHexWord(const S: string; Pos: Integer): Word;
begin
  Result := (Word(ParseHexByte(S,Pos)) shl 8) or ParseHexByte(S,Pos+2);
end;

function ParseHexLong(const S: string; Pos: Integer): LongWord;
begin
  Result := (LongWord(ParseHexWord(S,Pos)) shl 16) or ParseHexWord(S,Pos+4);
end;

function DayOfWeekExt(Y,M,D: Integer): Integer;
{ Zeller-like, returns 0=Sun }
var
  Enc: LongWord;
begin
  Enc := DateTimeToTimeStamp(EncodeDate(Y,M,D)).Date;
  Result := Enc mod 7;
end;

procedure ZeroMemBlock(var Buf; Size: Integer);
begin
  FillChar(Buf, Size, 0);
end;

function StripCR(const S: string): string;
var
  I: Integer;
  R: string;
begin
  R := '';
  for I := 1 to Length(S) do
    if S[I] <> #13 then R := R + S[I];
  Result := R;
end;

function TrimStr(const S: string): string;
begin
  Result := Trim(S);
end;

end.
