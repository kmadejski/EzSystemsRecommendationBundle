<?php
/**
 * @copyright Copyright (C) eZ Systems AS. All rights reserved.
 * @license For full copyright and license information view LICENSE file distributed with this source code.
 */
namespace EzSystems\RecommendationBundle\EventListener;

use eZ\Publish\API\Repository\UserService;
use eZ\Publish\Core\MVC\Symfony\Event\InteractiveLoginEvent as eZInteractiveLoginEvent;
use eZ\Publish\Core\MVC\Symfony\MVCEvents;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\AuthorizationChecker;
use Symfony\Component\HttpFoundation\Session\Session;
use GuzzleHttp\ClientInterface as GuzzleClient;
use GuzzleHttp\Exception\RequestException;
use Psr\Log\LoggerInterface;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent as SymfonyInteractiveLoginEvent;
use Symfony\Component\Security\Http\SecurityEvents;

/**
 * Sends notification to YooChoose servers when user is logged in.
 */
class Login implements EventSubscriberInterface
{
    /** @var array */
    private $options;

    /** @var \Symfony\Component\Security\Core\Authorization\AuthorizationChecker */
    private $authorizationChecker;

    /** @var \Symfony\Component\HttpFoundation\Session\Session */
    private $session;

    /** @var \GuzzleHttp\ClientInterface */
    private $guzzleClient;

    /** @var \eZ\Publish\API\Repository\UserService */
    private $userService;

    /** @var \Psr\Log\LoggerInterface|null */
    private $logger;

    /**
     * Constructs a Login event listener.
     *
     * @param \Symfony\Component\Security\Core\Authorization\AuthorizationChecker $authorizationChecker
     * @param \Symfony\Component\HttpFoundation\Session\Session $session
     * @param \GuzzleHttp\ClientInterface $guzzleClient
     * @param array $options
     * @param \eZ\Publish\API\Repository\UserService $userService
     * @param \Psr\Log\LoggerInterface $logger
     */
    public function __construct(
        AuthorizationChecker $authorizationChecker,
        Session $session,
        GuzzleClient $guzzleClient,
        $options = array(),
        UserService $userService,
        LoggerInterface $logger = null
    ) {
        $this->authorizationChecker = $authorizationChecker;
        $this->session = $session;
        $this->guzzleClient = $guzzleClient;
        $this->options = $options;
        $this->userService = $userService;
        $this->logger = $logger;
    }

    public static function getSubscribedEvents()
    {
        return [
            MVCEvents::INTERACTIVE_LOGIN => [
                ['onEzInteractiveLogin', 255]
            ],
            SecurityEvents::INTERACTIVE_LOGIN => [
                ['onSymfonySecurityInteractiveLogin', 255]
            ]
        ];
    }

    /**
     * Sets `customerId` option when service is created which allows to
     * inject parameter value according to siteaccess configuration.
     *
     * @param string $value
     */
    public function setCustomerId($value)
    {
        $this->options['customerId'] = $value;
    }

    public function onEzInteractiveLogin(eZInteractiveLoginEvent $event)
    {
        $this->logger->debug('Process onEzInteractiveLogin');
        return $this->process($event->getRequest(), $event->getAuthenticationToken());
    }

    public function onSymfonySecurityInteractiveLogin(SymfonyInteractiveLoginEvent $event)
    {
        $this->logger->debug('Process onSymfonySecurityInteractiveLogin');
        return $this->process($event->getRequest(), $event->getAuthenticationToken());
    }

    public function process(Request $request, TokenInterface $token)
    {
        if (!$this->authorizationChecker->isGranted('IS_AUTHENTICATED_FULLY') // user has just logged in
            || !$this->authorizationChecker->isGranted('IS_AUTHENTICATED_REMEMBERED') // user has logged in using remember_me cookie
        ) {
            return;
        }

        if (!$request->cookies->has('yc-session-id')) {
            $request->cookies->set('yc-session-id', $this->session->getId());
        }

        $notificationUri = sprintf($this->getNotificationEndpoint() . '%s/%s/%s',
            'login',
            $request->cookies->get('yc-session-id'),
            $this->getUser($token)
        );

        if ($this->logger !== null) {
            $this->logger->debug(sprintf('Send login event notification to YooChoose: %s', $notificationUri));
        }

        try {
            $response = $this->guzzleClient->get($notificationUri);

            if ($this->logger !== null) {
                $this->logger->debug(sprintf('Got %s from YooChoose login event notification', $response->getStatusCode()));
            }
        } catch (RequestException $e) {
            if ($this->logger !== null) {
                $this->logger->error(sprintf('YooChoose login event notification error: %s', $e->getMessage()));
            }
        }
    }

    /**
     * Returns notification API end-point.
     *
     * @return string
     */
    private function getNotificationEndpoint()
    {
        return sprintf(
            '%s/api/%s/',
            $this->options['trackingEndPoint'],
            $this->options['customerId']
        );
    }

    /**
     * Returns current username or ApiUser id.
     *
     * @param TokenInterface $authenticationToken
     *
     * @return int|string
     */
    private function getUser(TokenInterface $authenticationToken)
    {
        $user = $authenticationToken->getUser();

        if (is_string($user)) {
            return $user;
        }

        if (method_exists($user, 'getAPIUser')) {
            return $user->getAPIUser()->id;
        }

        return $authenticationToken->getUsername();
    }
}
