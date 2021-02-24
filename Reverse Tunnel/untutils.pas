unit untUtils;

{$mode delphi}

interface

uses
  Windows, Classes, SysUtils;

type
  TStringArray = array of String;

function SplitStr(strInput: String; strDelimiter: String; iLimit: Integer): TStringArray;
function ByteArrayToString(arr_bData: array of byte): String;

implementation

function SplitStr(strInput: String; strDelimiter: String; iLimit: Integer): TStringArray;
var
  strTemp: String;
  iIndex, iStringIndex: Integer;
begin
  strTemp := strInput;
  iStringIndex := 0;

  while (strTemp <> '') and (iStringIndex <> iLimit) do
  begin
    iIndex := Pos(strDelimiter, strTemp);

    if iIndex = 0 then
    begin
      SetLength(Result, iStringIndex + 1);
      Result[iStringIndex] := strTemp;
      break;
    end else
    begin
      SetLength(Result, iStringIndex + 1);
      Result[iStringIndex] := Copy(strTemp, 1, iIndex - 1);
      Delete(strTemp, 1, iIndex);
      Inc(iStringIndex);
    end;
  end;
end;

function ByteArrayToString(arr_bData: array of byte): String;
begin
  SetLength(Result, Length(arr_bData));
  CopyMemory(@Result[1], @arr_bData[0], Length(arr_bData));
end;

end.

