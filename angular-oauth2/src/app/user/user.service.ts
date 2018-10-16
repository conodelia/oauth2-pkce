import {Injectable} from '@angular/core';
import {User} from "./user";
import {Observable} from "rxjs/Observable";
import 'rxjs/add/operator/map';
import {HttpClient} from "@angular/common/http";
import {AppConfigService} from "../app.config.service";

@Injectable()
export class UserService {

  constructor(private appConfigService: AppConfigService, private http: HttpClient) {
  }

  public getUser(): Observable<User> {
    console.log("getting user info...");

    let principalResponse = this.http.get<PrincipalResponse>(`${this.appConfigService.getBackendUrl()}/user`);

    return principalResponse.map(r => {
      return {
        name: r.credentials.name
      }
    });
  }
}

interface PrincipalResponse {
  authorities: any[],
  details: any,
  authenticated: boolean,
  principal: string,
  credentials: {
    given_name: string,
    family_name: string,
    name: string,
    sub: string,
    email: string,
    email_verified: boolean,
    person_id: any
  },
  name: string
}
