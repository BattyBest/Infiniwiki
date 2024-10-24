{ pkgs ? import <nixpkgs> {}}:

pkgs.mkShell {
  packages = with pkgs; [ nginx python312 python312Packages.gunicorn python312Packages.openai python312Packages.flask python312Packages.flask-sqlalchemy python312Packages.flask-migrate python312Packages.flask-bcrypt python312Packages.flask-login python312Packages.wtforms python312Packages.flask-wtf python312Packages.apscheduler ];
}