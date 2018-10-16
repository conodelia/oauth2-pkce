import {Injectable} from '@angular/core';
import {Observable} from "rxjs/Observable";
import {TokenService} from "./token.service";
import "rxjs/add/operator/mergeMap";
import {Router} from "@angular/router";
import {AppConfigService} from "../app.config.service";
import {AuthenticatedUser} from "./authenticated-user";
import {UserService} from "../user/user.service";

@Injectable()
export class AuthenticationService {
  public code: String;
  private _isAuthenticated: boolean = false;
  private _authenticatedUser: AuthenticatedUser = null;

  constructor(
    private appConfigService: AppConfigService,
    private tokenService: TokenService,
    private userService: UserService,
    private router: Router
  ) { }

  public get isAuthenticated(): Observable<AuthenticatedUser> {
    if(this._authenticatedUser == null) {
      let maybeUser = this.userService.getUser();

      return maybeUser.map(u => {
        return {
          isAuthenticated: true,
          user: u
        }
      });
    } else {
      Observable.create(this._authenticatedUser)
    }
  }

  public login(): void {
    const loginUrl = `${this.appConfigService.getBackendUrl()}${this.appConfigService.getLoginEndpoint()}`;

    console.log(`redirect to: ${loginUrl}`);
    this.router.navigate([`${loginUrl}`]);
  }

  public exchangeToken(code: string): Observable<void> {
    return this.tokenService.getToken(code).map(
      () => {
        console.log(`got token for code: ${code}`);
        this._isAuthenticated = true;
      }
    );
  }
}
