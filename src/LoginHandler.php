<?php


namespace App;


use Doctrine\DBAL\Connection;
use Firebase\JWT\JWT;
use TopicAdvisor\Lambda\RuntimeApi\Http\HttpRequestInterface;
use TopicAdvisor\Lambda\RuntimeApi\Http\HttpResponse;
use TopicAdvisor\Lambda\RuntimeApi\InvocationRequestHandlerInterface;
use TopicAdvisor\Lambda\RuntimeApi\InvocationRequestInterface;
use TopicAdvisor\Lambda\RuntimeApi\InvocationResponseInterface;

class LoginHandler implements InvocationRequestHandlerInterface
{
    /**
     * @var Connection
     */
    private $connection;

    /**
     * @param Connection $connection
     */
    public function __construct(Connection $connection)
    {
        $this->connection = $connection;
    }

    /**
     * @param InvocationRequestInterface $request
     * @return bool
     */
    public function canHandle(InvocationRequestInterface $request): bool
    {
        return $request instanceof HttpRequestInterface;
    }

    /**
     * @param InvocationRequestInterface $request
     * @return void
     */
    public function preHandle(InvocationRequestInterface $request)
    {
    }

    /**
     * @param InvocationRequestInterface $request
     * @return InvocationResponseInterface
     * @throws \Exception
     */
    public function handle(InvocationRequestInterface $request): InvocationResponseInterface
    {
        if (!$request instanceof HttpRequestInterface) {
            throw new \LogicException('Must be invoked with HttpRequestInterface only');
        }

        $response = new HttpResponse($request->getInvocationId());

        if ($request->getMethod() !== 'POST') {
            $response->setStatusCode(405);
            return $response;
        }

        $body = \json_decode($request->getBody());

        if (!\is_object($body)
            || !isset($body->username) || !\is_string($body->username)
            || !isset($body->password) || !\is_string($body->password)) {
            $response->setStatusCode(400);
            return $response;
        }

        $sql = "SELECT * FROM users WHERE username = :username";
        $stmt = $this->connection->prepare($sql);
        $stmt->bindValue('username', $body->username);
        $stmt->execute();

        $row = $stmt->fetch();

        if (!\password_verify($body->password, $row['password'])) {
            $response->setStatusCode(403);
            return $response;
        }

        $token = [
            'aud' => 'wueww-admin.metafnord.de',
            'iss' => 'wueww-admin.metafnord.de',
            'sub' => $row['id'],
            'role' => $row['role'],
            'iat' => \time(),
            'nbf' => \time(),
            'exp' => \time() + 3600 * 2,
        ];

        $jwt = JWT::encode($token, \getenv('key.pem'), 'RS256');

        $response = new HttpResponse($request->getInvocationId());
        $response->setStatusCode(200);
        $response->setBody($jwt);

        return $response;
    }

    /**
     * @param InvocationRequestInterface $request
     * @param InvocationResponseInterface $response
     * @return void
     */
    public function postHandle(InvocationRequestInterface $request, InvocationResponseInterface $response)
    {
    }
}