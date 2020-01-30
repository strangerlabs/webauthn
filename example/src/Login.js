
/**
 * Dependencies
 * @ignore
 */
import React, { useState } from 'react'
import { Container, Row, Col, Form, Button, Alert } from 'react-bootstrap'
import Client from 'webauthn/client'

/**
 * Module Dependencies
 * @ignore
 */

/**
 * Login
 * @ignore
 */
function Login (props) {
  const [name, setName] = useState('')
  const [username, setUsername] = useState('')
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [webauthn] = useState(new Client())

  function onRegister () {
    if (username === "") {
      setError('Please enter a username')
      return
    }
    webauthn.register({ name, username }).then(response => {
      console.log('Register response: ', response)
      setSuccess('Registration successful. Try logging in.')
    });
  }

  function onLogin () {
    if (username === "") {
      setError('Please enter a username')
      return
    }
    webauthn.login({ username }).then(response => {
      console.log('Login response: ', response);
      if (response && response.status === "ok")
        props.onLogin({
          username,
        });
    });
  }

  return (
    <Container>
      <Row style={{ paddingTop: 80 }}>
        <Col>
          {error && <Alert variant="danger" dismissible onClose={() => setError('')}>
            {error}
          </Alert>}
          {success && <Alert variant="success" dismissible onClose={() => setSuccess('')}>
            {success}
          </Alert>}
        </Col>
      </Row>
      <Row>
        <Col>
          <h3>Register</h3>
          <Form>
            <Form.Group>
              <Form.Label>Username</Form.Label>
              <Form.Control
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
              ></Form.Control>
            </Form.Group>
            <Form.Group>
              <Form.Label>Name</Form.Label>
              <Form.Control
                type="text"
                value={name}
                onChange={e => setName(e.target.value)}
              ></Form.Control>
              <Form.Text className="text-muted">This name will be displayed publicly.</Form.Text>
            </Form.Group>
            <Button variant="primary" onClick={onRegister}>
              Register
            </Button>
          </Form>
        </Col>
        <Col>
          <h3>Login</h3>
          <Form>
            <Form.Group>
              <Form.Label>Username</Form.Label>
              <Form.Control type="text" value={username} onChange={e => setUsername(e.target.value)}></Form.Control>
            </Form.Group>
            <Button variant="primary" onClick={onLogin}>
              Login
            </Button>
          </Form>
        </Col>
      </Row>
    </Container>
  )
}

/**
 * Exports
 * @ignore
 */
export default Login;
