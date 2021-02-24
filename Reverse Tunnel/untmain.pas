unit untmain;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, ComCtrls,
  Menus, untServerSocket;

type

  { TForm1 }

  TForm1 = class(TForm)
    lvConnections: TListView;
    MainMenu1: TMainMenu;
    MenuItem1: TMenuItem;
    MenuItem2: TMenuItem;
    miStartServer: TMenuItem;
    pmConnectionsMenu: TPopupMenu;
    procedure FormCreate(Sender: TObject);
    procedure miStartServerClick(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  Form1: TForm1;
  ServerSocket: TServerSocket;

implementation

{$R *.lfm}

{ TForm1 }

procedure TForm1.FormCreate(Sender: TObject);
begin

end;

procedure TForm1.miStartServerClick(Sender: TObject);
begin
  ServerSocket := TServerSocket.Create(555);
end;

end.

