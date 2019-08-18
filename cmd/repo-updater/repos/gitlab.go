package repos

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	multierror "github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"
<<<<<<< HEAD
	"github.com/sourcegraph/sourcegraph/pkg/conf/reposource"
	"github.com/sourcegraph/sourcegraph/pkg/extsvc/gitlab"
	"github.com/sourcegraph/sourcegraph/pkg/httpcli"
	"github.com/sourcegraph/sourcegraph/pkg/jsonc"
=======
	"github.com/sourcegraph/sourcegraph/pkg/api"
	"github.com/sourcegraph/sourcegraph/pkg/atomicvalue"
	"github.com/sourcegraph/sourcegraph/pkg/conf"
	"github.com/sourcegraph/sourcegraph/pkg/conf/reposource"
	"github.com/sourcegraph/sourcegraph/pkg/extsvc/gitlab"
	"github.com/sourcegraph/sourcegraph/pkg/repoupdater/protocol"
>>>>>>> origin/2.13
	"github.com/sourcegraph/sourcegraph/schema"
	log15 "gopkg.in/inconshreveable/log15.v2"
)

<<<<<<< HEAD
// A GitLabSource yields repositories from a single GitLab connection configured
// in Sourcegraph via the external services configuration.
type GitLabSource struct {
	svc     *ExternalService
	config  *schema.GitLabConnection
	exclude map[string]bool
	baseURL *url.URL // URL with path /api/v4 (no trailing slash)
	client  *gitlab.Client
}

// NewGitLabSource returns a new GitLabSource from the given external service.
func NewGitLabSource(svc *ExternalService, cf *httpcli.Factory) (*GitLabSource, error) {
	var c schema.GitLabConnection
	if err := jsonc.Unmarshal(svc.Config, &c); err != nil {
		return nil, fmt.Errorf("external service id=%d config error: %s", svc.ID, err)
=======
var gitlabConnections = atomicvalue.New()

func init() {
	conf.Watch(func() {
		gitlabConnections.Set(func() interface{} {
			gitlabConf := conf.Get().Gitlab

			var hasGitLabDotComConnection bool
			for _, c := range gitlabConf {
				u, _ := url.Parse(c.Url)
				if u != nil && (u.Hostname() == "gitlab.com" || u.Hostname() == "www.gitlab.com") {
					hasGitLabDotComConnection = true
					break
				}
			}
			if !hasGitLabDotComConnection {
				// Add a GitLab.com entry by default, to support navigating to URL paths like
				// /gitlab.com/foo/bar to auto-add that project.
				gitlabConf = append(gitlabConf, &schema.GitLabConnection{
					ProjectQuery:                []string{"none"}, // don't try to list all repositories during syncs
					Url:                         "https://gitlab.com",
					InitialRepositoryEnablement: true,
				})
			}

			var conns []*gitlabConnection
			for _, c := range gitlabConf {
				conn, err := newGitLabConnection(c)
				if err != nil {
					log15.Error("Error processing configured GitLab connection. Skipping it.", "url", c.Url, "error", err)
					continue
				}
				conns = append(conns, conn)
			}
			return conns
		})
		gitLabRepositorySyncWorker.restart()
	})
}

// getGitLabConnection returns the GitLab connection (config + API client) that is responsible for
// the repository specified by the args.
func getGitLabConnection(args protocol.RepoLookupArgs) (*gitlabConnection, error) {
	gitlabConnections := gitlabConnections.Get().([]*gitlabConnection)
	if args.ExternalRepo != nil && args.ExternalRepo.ServiceType == gitlab.GitLabServiceType {
		// Look up by external repository spec.
		for _, conn := range gitlabConnections {
			if args.ExternalRepo.ServiceID == conn.baseURL.String() {
				return conn, nil
			}
		}
		return nil, errors.Wrap(gitlab.ErrNotFound, fmt.Sprintf("no configured GitLab connection with URL: %q", args.ExternalRepo.ServiceID))
>>>>>>> origin/2.13
	}
	return newGitLabSource(svc, &c, cf)
}

func newGitLabSource(svc *ExternalService, c *schema.GitLabConnection, cf *httpcli.Factory) (*GitLabSource, error) {
	baseURL, err := url.Parse(c.Url)
	if err != nil {
		return nil, err
	}
	baseURL = NormalizeBaseURL(baseURL)

	if cf == nil {
		cf = NewHTTPClientFactory()
	}

<<<<<<< HEAD
	var opts []httpcli.Opt
	if c.Certificate != "" {
		pool, err := newCertPool(c.Certificate)
		if err != nil {
			return nil, err
=======
	ghrepoToRepoInfo := func(proj *gitlab.Project, conn *gitlabConnection) *protocol.RepoInfo {
		return &protocol.RepoInfo{
			URI:          gitlabProjectToRepoPath(conn, proj),
			ExternalRepo: gitlab.GitLabExternalRepoSpec(proj, *conn.baseURL),
			Description:  proj.Description,
			Fork:         proj.ForkedFromProject != nil,
			Archived:     proj.Archived,
			VCS: protocol.VCSInfo{
				URL: conn.authenticatedRemoteURL(proj),
			},
			Links: &protocol.RepoLinks{
				Root:   proj.WebURL,
				Tree:   proj.WebURL + "/tree/{rev}/{path}",
				Blob:   proj.WebURL + "/blob/{rev}/{path}",
				Commit: proj.WebURL + "/commit/{commit}",
			},
>>>>>>> origin/2.13
		}
		opts = append(opts, httpcli.NewCertPoolOpt(pool))
	}

	cli, err := cf.Doer(opts...)
	if err != nil {
		return nil, err
	}

<<<<<<< HEAD
	exclude := make(map[string]bool, len(c.Exclude))
	for _, r := range c.Exclude {
		if r.Name != "" {
			exclude[r.Name] = true
=======
	if args.ExternalRepo != nil && args.ExternalRepo.ServiceType == gitlab.GitLabServiceType {
		// Look up by external repository spec.
		id, err := strconv.Atoi(args.ExternalRepo.ID)
		if err != nil {
			return nil, true, err
		}
		proj, err := conn.client.GetProject(ctx, id, "")
		if proj != nil {
			repo = ghrepoToRepoInfo(proj, conn)
>>>>>>> origin/2.13
		}

		if r.Id != 0 {
			exclude[strconv.Itoa(r.Id)] = true
		}
	}

	return &GitLabSource{
		svc:     svc,
		config:  c,
		exclude: exclude,
		baseURL: baseURL,
		client:  gitlab.NewClientProvider(baseURL, cli).GetPATClient(c.Token, ""),
	}, nil
}

// ListRepos returns all GitLab repositories accessible to all connections configured
// in Sourcegraph via the external services configuration.
func (s GitLabSource) ListRepos(ctx context.Context) (repos []*Repo, err error) {
	projs, err := s.listAllProjects(ctx)
	for _, proj := range projs {
		repos = append(repos, s.makeRepo(proj))
	}
	return repos, err
}

// ExternalServices returns a singleton slice containing the external service.
func (s GitLabSource) ExternalServices() ExternalServices {
	return ExternalServices{s.svc}
}

<<<<<<< HEAD
func (s GitLabSource) makeRepo(proj *gitlab.Project) *Repo {
	urn := s.svc.URN()
	return &Repo{
		Name: string(reposource.GitLabRepoName(
			s.config.RepositoryPathPattern,
			s.baseURL.Hostname(),
			proj.PathWithNamespace,
		)),
		URI: string(reposource.GitLabRepoName(
			"",
			s.baseURL.Hostname(),
			proj.PathWithNamespace,
		)),
		ExternalRepo: gitlab.ExternalRepoSpec(proj, *s.baseURL),
		Description:  proj.Description,
		Fork:         proj.ForkedFromProject != nil,
		Enabled:      true,
		Archived:     proj.Archived,
		Sources: map[string]*SourceInfo{
			urn: {
				ID:       urn,
				CloneURL: s.authenticatedRemoteURL(proj),
=======
// updateGitLabProjects ensures that all provided repositories exist in the repository table.
func updateGitLabProjects(ctx context.Context, conn *gitlabConnection) {
	projs := conn.listAllProjects(ctx)

	repoChan := make(chan repoCreateOrUpdateRequest)
	defer close(repoChan)
	go createEnableUpdateRepos(ctx, fmt.Sprintf("gitlab:%s", conn.config.Token), repoChan)
	for proj := range projs {
		repoChan <- repoCreateOrUpdateRequest{
			RepoCreateOrUpdateRequest: api.RepoCreateOrUpdateRequest{
				RepoURI:      gitlabProjectToRepoPath(conn, proj),
				ExternalRepo: gitlab.GitLabExternalRepoSpec(proj, *conn.baseURL),
				Description:  proj.Description,
				Fork:         proj.ForkedFromProject != nil,
				Archived:     proj.Archived,
				Enabled:      conn.config.InitialRepositoryEnablement,
>>>>>>> origin/2.13
			},
		},
		Metadata: proj,
	}
}

// authenticatedRemoteURL returns the GitLab projects's Git remote URL with the configured GitLab personal access
// token inserted in the URL userinfo, for repositories needing authentication.
func (s *GitLabSource) authenticatedRemoteURL(proj *gitlab.Project) string {
	if s.config.GitURLType == "ssh" {
		return proj.SSHURLToRepo // SSH authentication must be provided out-of-band
	}
	if s.config.Token == "" || !proj.RequiresAuthentication() {
		return proj.HTTPURLToRepo
	}
	u, err := url.Parse(proj.HTTPURLToRepo)
	if err != nil {
		log15.Warn("Error adding authentication to GitLab repository Git remote URL.", "url", proj.HTTPURLToRepo, "error", err)
		return proj.HTTPURLToRepo
	}
	// Any username works; "git" is not special.
	u.User = url.UserPassword("git", s.config.Token)
	return u.String()
}

func (s *GitLabSource) excludes(p *gitlab.Project) bool {
	return s.exclude[p.PathWithNamespace] || s.exclude[strconv.Itoa(p.ID)]
}

func (s *GitLabSource) listAllProjects(ctx context.Context) ([]*gitlab.Project, error) {
	type batch struct {
		projs []*gitlab.Project
		err   error
	}

	ch := make(chan batch)

	var wg sync.WaitGroup

	projch := make(chan *schema.GitLabProject)
	for i := 0; i < 5; i++ { // 5 concurrent requests
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range projch {
				proj, err := s.client.GetProject(ctx, gitlab.GetProjectOp{
					ID:                p.Id,
					PathWithNamespace: p.Name,
					CommonOp:          gitlab.CommonOp{NoCache: true},
				})

				if err != nil {
					// TODO(tsenart): When implementing dry-run, reconsider alternatives to return
					// 404 errors on external service config validation.
					if gitlab.IsNotFound(err) {
						log15.Warn("skipping missing gitlab.projects entry:", "name", p.Name, "id", p.Id, "err", err)
						continue
					}
					ch <- batch{err: errors.Wrapf(err, "gitlab.projects: id: %d, name: %q", p.Id, p.Name)}
				} else {
					ch <- batch{projs: []*gitlab.Project{proj}}
				}

				time.Sleep(s.client.RateLimit.RecommendedWaitForBackgroundOp(1))
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(projch)
		for _, p := range s.config.Projects {
			select {
			case projch <- p:
			case <-ctx.Done():
				return
			}
		}
	}()

	for _, projectQuery := range s.config.ProjectQuery {
		if projectQuery == "none" {
			continue
		}

		const perPage = 100
		wg.Add(1)
		go func(projectQuery string) {
			defer wg.Done()

			url, err := projectQueryToURL(projectQuery, perPage) // first page URL
			if err != nil {
				ch <- batch{err: errors.Wrapf(err, "invalid GitLab projectQuery=%q", projectQuery)}
				return
			}

			for {
				if err := ctx.Err(); err != nil {
					ch <- batch{err: err}
					return
				}
				projects, nextPageURL, err := s.client.ListProjects(ctx, url)
				if err != nil {
					ch <- batch{err: errors.Wrapf(err, "error listing GitLab projects: url=%q", url)}
					return
				}
				ch <- batch{projs: projects}
				if nextPageURL == nil {
					return
				}
				url = *nextPageURL

				// 0-duration sleep unless nearing rate limit exhaustion
				time.Sleep(s.client.RateLimit.RecommendedWaitForBackgroundOp(1))
			}
		}(projectQuery)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	seen := make(map[int]bool)
	errs := new(multierror.Error)
	var projects []*gitlab.Project

	for b := range ch {
		if b.err != nil {
			errs = multierror.Append(errs, b.err)
			continue
		}

		for _, proj := range b.projs {
			if !seen[proj.ID] && !s.excludes(proj) {
				projects = append(projects, proj)
				seen[proj.ID] = true
			}
		}
	}

	return projects, errs.ErrorOrNil()
}

var schemeOrHostNotEmptyErr = errors.New("scheme and host should be empty")

func projectQueryToURL(projectQuery string, perPage int) (string, error) {
	// If all we have is the URL query, prepend "projects"
	if strings.HasPrefix(projectQuery, "?") {
		projectQuery = "projects" + projectQuery
	} else if projectQuery == "" {
		projectQuery = "projects"
	}

	u, err := url.Parse(projectQuery)
	if err != nil {
		return "", err
	}
	if u.Scheme != "" || u.Host != "" {
		return "", schemeOrHostNotEmptyErr
	}
	normalizeQuery(u, perPage)

	return u.String(), nil
}

func normalizeQuery(u *url.URL, perPage int) {
	q := u.Query()
	if q.Get("order_by") == "" && q.Get("sort") == "" {
		// Apply default ordering to get the likely more relevant projects first.
		q.Set("order_by", "last_activity_at")
	}
	q.Set("per_page", strconv.Itoa(perPage))
	u.RawQuery = q.Encode()
}
