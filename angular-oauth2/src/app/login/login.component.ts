import {Component, OnInit} from '@angular/core';
import {User} from "../user/user";
import {AuthenticationService} from "../auth/authentication.service";
import {ActivatedRoute} from "@angular/router";
import {AppConfigService} from "../app.config.service";

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss']
})
export class LoginComponent implements OnInit {

  public user: User;
  private _isAuthenticated = false;

  constructor(
    private appConfigService: AppConfigService,
    private authenticationService: AuthenticationService,
    private route: ActivatedRoute
  ) {
  }

  ngOnInit() {
    console.log("login component");

    this.authenticationService.isAuthenticated.subscribe(a => {
      if(a.isAuthenticated) {
        this._isAuthenticated = a.isAuthenticated;
        this.user = a.user;

        console.log(this.user)
      } else {
        let code = this.route.queryParams['code'];
        if(code) {
          this.authenticationService.exchangeToken(code.value);
        }
      }
    });
  }

  public get authenticated() {
    return this._isAuthenticated;
  }

  public get unauthenticated() {
    return !(this._isAuthenticated);
  }

  public get loginUrl() {
    return `${this.appConfigService.getBackendUrl()}${this.appConfigService.getLoginEndpoint()}?redirect_uri=${this.appConfigService.getRedirectUri()}`;
  }

  public get logoutUrl() {
    return `${this.appConfigService.getBackendUrl()}${this.appConfigService.getLogoutEndpoint()}`;
  }
}
