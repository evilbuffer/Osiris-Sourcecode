unit untclientsocket;

{$mode delphi}

interface

uses
  Windows, Winsock, Classes, SysUtils;

type
  TClientSocket = class
    private
      m_hClient: TSocket;
      m_ClientAddress: TSockAddrIn;
    public
      constructor Create(hClient: TSocket; ClientAddress: TSockAddrIn);
      procedure SendData(strData: String);
      function GetIPAddress: String;
      function GetSocket: TSocket;
      procedure Disconnect;
  end;

implementation

constructor TClientSocket.Create(hClient: TSocket; ClientAddress: TSockAddrIn);
begin
  m_hClient := hClient;
  m_ClientAddress := ClientAddress;
end;

procedure TClientSocket.SendData(strData: String);
begin
  send(m_hClient, strData[1], Length(strData), 0);
end;

function TClientSocket.GetIPAddress: String;
begin
  Result := inet_ntoa(m_ClientAddress.sin_addr);
end;

function TClientSocket.GetSocket: TSocket;
begin
  Result := m_hClient;
end;

procedure TClientSocket.Disconnect;
begin
  closesocket(m_hClient);
  m_hClient := INVALID_SOCKET;
end;

end.

