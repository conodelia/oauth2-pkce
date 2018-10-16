import {Injectable} from '@angular/core';
import {HttpClient} from "@angular/common/http";
import {Observable} from "rxjs/Observable";
import {AppConfigService} from "../app.config.service";

@Injectable()
export class TokenService {

  constructor(
    private appConfigService: AppConfigService,
    private http: HttpClient
  ) { }

  public getToken(code: string): Observable<void> {
    let url = `${this.appConfigService.getBackendUrl()}${this.appConfigService.getLoginEndpoint()}?code=${code}&redirect_uri=${this.appConfigService.getRedirectUri()}`;
    console.log(`GET ${url}`);

    return this.http.get<void>(url);
  }
}
