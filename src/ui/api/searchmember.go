// Copyright (c) 2017 VMware, Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/vmware/harbor/src/common"
	"github.com/vmware/harbor/src/common/dao"
	"github.com/vmware/harbor/src/common/models"
	"github.com/vmware/harbor/src/common/utils/log"
)

// SearchAPI handles requesst to search/:username

// Get ...
func (s *SearchAPI) GetByUsername() {
	keyword := s.GetString("q")
	username := s.GetStringFromPath(":username")

	log.Warningf("request param q: %s,member:%s", keyword,username)
	isAuthenticated := s.SecurityCtx.IsAuthenticated()
	isSysAdmin := s.SecurityCtx.IsSysAdmin()

	var projects []*models.Project
	var err error
	var user *models.User

	if isAuthenticated && isSysAdmin {
		log.Warningf("user is authenticate and isSystemAdmin")
		queryUser := models.User{Username:username}
		err := validateName(queryUser)
		if err != nil {
			log.Warningf("Bad request in Register: %v", err)
			s.RenderError(http.StatusBadRequest, "register error:"+err.Error())
			return
		}

		log.Warningf("after validate")
		user,err = dao.GetUser(queryUser)

		if err != nil {
			log.Errorf("get user by username error: %v", err)
			s.CustomAbort(http.StatusInternalServerError, "Internal error.")
		}
		if user == nil {
			log.Warning("user with username : %S not found!",username)
			s.RenderError(http.StatusConflict, "user not found!")
			return
		}
		log.Warningf("get user success")
		projects, err = s.ProjectMgr.GetPublic()
		if err != nil {
			s.ParseAndHandleError("failed to get projects", err)
			return
		}
		log.Warningf("after get public projects")
		//取出projects
		mys, mErr := dao.GetProjects(&models.ProjectQueryParam{
			Member: &models.MemberQuery{
				Name: user.Username,
			},
		})

		if mErr != nil {
			s.HandleInternalServerError(fmt.Sprintf(
				"failed to get projects: %v", err))
			return
		}
		log.Warningf("after get projects of user:%s",username)
		exist := map[int64]bool{}
		for _, p := range projects {
			exist[p.ProjectID] = true
		}

		for _, p := range mys {
			if !exist[p.ProjectID] {
				projects = append(projects, p)
			}
		}

	}

	projectSorter := &models.ProjectSorter{Projects: projects}
	sort.Sort(projectSorter)
	projectResult := []*models.Project{}
	for _, p := range projects {
		if len(keyword) > 0 && !strings.Contains(p.Name, keyword) {
			continue
		}

		roles := getProjectRoles(p,user)
		if len(roles) != 0 {
			p.Role = roles[0]
		}

		if p.Role == common.RoleProjectAdmin {
			p.Togglable = true
		}

		total, err := dao.GetTotalOfRepositories(&models.RepositoryQuery{
			ProjectIDs: []int64{p.ProjectID},
		})
		if err != nil {
			log.Errorf("failed to get total of repositories of project %d: %v", p.ProjectID, err)
			s.CustomAbort(http.StatusInternalServerError, "")
		}

		p.RepoCount = total

		projectResult = append(projectResult, p)
	}

	repositoryResult, err := filterRepositories(projects, keyword)
	if err != nil {
		log.Errorf("failed to filter repositories: %v", err)
		s.CustomAbort(http.StatusInternalServerError, "")
	}

	result := &searchResult{Project: projectResult, Repository: repositoryResult}
	s.Data["json"] = result
	s.ServeJSON()
}

func getProjectRoles(project *models.Project,user *models.User) []int {
	roles := []int{}
	roleList, err := dao.GetUserProjectRoles(user.UserID, project.ProjectID, common.UserMember)
	if err != nil {
		log.Errorf("failed to get roles of user %d to project %d: %v", user.UserID, project.ProjectID, err)
		return roles
	}

	for _, role := range roleList {
		switch role.RoleCode {
		case "MDRWS":
			roles = append(roles, common.RoleProjectAdmin)
		case "RWS":
			roles = append(roles, common.RoleDeveloper)
		case "RS":
			roles = append(roles, common.RoleGuest)
		}
	}
	return roles
}
